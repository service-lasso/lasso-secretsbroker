package main

import (
 "crypto/sha256"
 "crypto/x509"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "net/http"
 "os"
 "reflect"
 "strconv"
 "sync"
 "time"
)
type Result struct { Accepted bool `json:"accepted"`; Error string `json:"error,omitempty"`; ChainSha256 [][]string `json:"chainSha256"`; RootsMode string `json:"rootsMode"`; RepeatedConcurrentStable bool `json:"repeatedConcurrentStable"`; Calls int `json:"calls"` }
func cert(p string) *x509.Certificate { b,e:=os.ReadFile(p);if e!=nil{panic(e)};c,e:=x509.ParseCertificate(b);if e!=nil{panic(e)};return c }
func main(){
 if len(os.Args)==2 && os.Args[1]=="https" {
  client:=&http.Client{Timeout:20*time.Second};r,e:=client.Get("https://github.com/");if e!=nil{panic(e)};defer r.Body.Close()
  fmt.Printf("{\"liveTrustedHttps\":true,\"status\":%d,\"nativeRoots\":true}\n",r.StatusCode);return
 }
 if len(os.Args)<5{panic("host unix-time rootsDER-or-dash certDER...")}
 sec,e:=strconv.ParseInt(os.Args[2],10,64);if e!=nil{panic(e)}
 leaf:=cert(os.Args[4]);opts:=x509.VerifyOptions{DNSName:os.Args[1],CurrentTime:time.Unix(sec,0),Intermediates:x509.NewCertPool()}
 mode:="nil-native-host-roots";if os.Args[3]!="-"{opts.Roots=x509.NewCertPool();opts.Roots.AddCert(cert(os.Args[3]));mode="custom-root-go-policy"}
 for _,p:=range os.Args[5:]{opts.Intermediates.AddCert(cert(p))}
 verify:=func() Result { chains,err:=leaf.Verify(opts);r:=Result{Accepted:err==nil,RootsMode:mode};if err!=nil{r.Error=err.Error()};for _,chain:=range chains{hashes:=[]string{};for _,c:=range chain{h:=sha256.Sum256(c.Raw);hashes=append(hashes,hex.EncodeToString(h[:]))};r.ChainSha256=append(r.ChainSha256,hashes)};return r }
 baseline:=verify();stable:=true;var mutex sync.Mutex;var wg sync.WaitGroup
 for i:=0;i<100;i++{wg.Add(1);go func(){defer wg.Done();r:=verify();mutex.Lock();if !reflect.DeepEqual(r,baseline){stable=false};mutex.Unlock()}()};wg.Wait()
 baseline.RepeatedConcurrentStable=stable;baseline.Calls=101;b,e:=json.Marshal(baseline);if e!=nil{panic(e)};fmt.Println(string(b));if !stable{os.Exit(1)}
}
