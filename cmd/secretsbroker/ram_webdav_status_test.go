package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestRAMInventoryAuthenticationAccountingAndLifecycle(t *testing.T) {
	b, close := ramFixture(t)
	handler := newHandler(runtimeState{}, b, localAPISecurity{token: "test-token"})
	request := func(method, query, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/v1/file-grants/status"+query, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, token := range []string{"", "incorrect"} {
		if w := request("GET", "", token); w.Code != 401 {
			t.Fatalf("inventory auth: %d", w.Code)
		}
	}
	if w := request("POST", "", "test-token"); w.Code != 405 {
		t.Fatal("inventory allows writes")
	}
	for _, query := range []string{"?limit=0", "?limit=201", "?cursor=-1", "?cursor=131073", "?limit=1&limit=2", "?token=private"} {
		if w := request("GET", query, "test-token"); w.Code != 400 {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
	grant, err := b.ramFiles.create("owner", []ramFileInput{{"a", "synthetic-private"}, {"folder/b", "other"}}, ramFileOwner{WorkspaceID: "workspace", ServiceID: "echo-service"})
	if err != nil {
		t.Fatal(err)
	}
	url := grant.BaseURL + "/" + grant.Token + "/a"
	for _, method := range []string{"HEAD", "GET", "GET"} {
		code, _ := davRequest(t, method, url, "", nil)
		if code != 200 {
			t.Fatal("read failed")
		}
	}
	davRequest(t, "GET", grant.BaseURL+"/"+grant.Token+"/missing", "", nil)
	davRequest(t, "PROPFIND", grant.BaseURL+"/"+grant.Token+"/", "", map[string]string{"Depth": "1"})
	w := request("GET", "?limit=1", "test-token")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("inventory unavailable/cacheable")
	}
	for _, forbidden := range []string{grant.Token, "synthetic-private", "other", grant.BaseURL} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatal("private material in inventory")
		}
	}
	var status ramStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "listening" || status.FileCount != 2 || status.ActiveGrants != 1 || status.Downloads != 2 || status.ServedBytes != 34 || status.NextCursor != "1" || len(status.Files) != 1 {
		t.Fatalf("incorrect counts: %+v", status)
	}
	row := status.Files[0]
	if row.ServiceID != "echo-service" || row.WorkspaceID != "workspace" || row.Downloads != 2 || row.SizeBytes != 17 || row.LastAccessAt == "" {
		t.Fatalf("incorrect row: %+v", row)
	}
	page := request("GET", "?limit=1&cursor=1", "test-token")
	status = ramStatusResponse{}
	if err := json.Unmarshal(page.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Files) != 1 || status.Files[0].Path != "folder/b" || status.Files[0].Downloads != 0 || status.NextCursor != "" {
		t.Fatalf("incorrect next page: %+v", status)
	}
	replacement, err := b.ramFiles.create("owner", []ramFileInput{{"a", "new"}}, ramFileOwner{ServiceID: "echo-service"})
	if err != nil {
		t.Fatal(err)
	}
	status = b.ramFiles.status(0, 100)
	if status.Downloads != 0 || status.FileCount != 1 || status.UsedBytes != 3 || status.Files[0].GrantID == row.GrantID {
		t.Fatal("rotation retained stale usage")
	}
	b.ramFiles.revoke(replacement.Token)
	if status = b.ramFiles.status(0, 100); status.ActiveGrants != 0 || status.FileCount != 0 || status.Downloads != 0 {
		t.Fatal("revoked grant remains visible")
	}
	close()
	if status = b.ramFiles.status(0, 100); status.State != "stopped" || status.UsedBytes != 0 {
		t.Fatal("stopped provider marked listening")
	}
	if _, err := b.ramFiles.create("late", []ramFileInput{{"a", "x"}}); err == nil {
		t.Fatal("closed provider accepts new grants")
	}
}

type failedRAMWriter struct {
	header http.Header
	count  int
}

func (w *failedRAMWriter) Header() http.Header { return w.header }
func (*failedRAMWriter) WriteHeader(int)       {}
func (w *failedRAMWriter) Write([]byte) (int, error) {
	return w.count, errors.New("client disconnected")
}

func TestRAMInventoryFailedWritesDoNotCountDownloads(t *testing.T) {
	b, _ := ramFixture(t)
	grant, err := b.ramFiles.create("owner", []ramFileInput{{"a", "synthetic"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", grant.BaseURL+"/"+grant.Token+"/a", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	b.ramFiles.ServeHTTP(&failedRAMWriter{header: make(http.Header), count: 2}, r)
	b.ramFiles.ServeHTTP(&failedRAMWriter{header: make(http.Header), count: -1}, r)
	status := b.ramFiles.status(0, 100)
	if status.Downloads != 0 || status.ServedBytes != 2 || status.Files[0].LastAccessAt != "" {
		t.Fatal("failed read counted as completed")
	}
}

func TestRAMInventoryBoundsEncodedMetadata(t *testing.T) {
	b, _ := ramFixture(t)
	files := make([]ramFileInput, 128)
	for i := range files {
		files[i] = ramFileInput{Path: strconv.Itoa(i), Content: "x"}
	}
	if _, err := b.ramFiles.create("owner", files, ramFileOwner{WorkspaceID: strings.Repeat("\x01", 2000), ServiceID: "app"}); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(runtimeState{}, b, localAPISecurity{token: "test-token"})
	r := httptest.NewRequest("GET", "/v1/file-grants/status?limit=200", nil)
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.Len() > 768<<10 {
		t.Fatal("inventory response exceeded budget")
	}
	var status ramStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Files) == 0 || len(status.Files) >= 128 || status.NextCursor != strconv.Itoa(len(status.Files)) {
		t.Fatal("budget pagination lost rows")
	}
}
