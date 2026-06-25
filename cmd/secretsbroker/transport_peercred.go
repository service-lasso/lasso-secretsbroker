package main

func unixPeerUIDAuthorized(peerUID, allowedUID int) bool {
	return peerUID >= 0 && peerUID == allowedUID
}
