package test

import (
	"fmt"
	"reflect"

	"github.com/golang/mock/gomock"
	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerIDMatcher matches given peer.ID to a string
type PeerIDMatcher struct {
	val string
}

func NewPeerIDMatcher(val string) *PeerIDMatcher {
	return &PeerIDMatcher{val: val}
}

func (m *PeerIDMatcher) Matches(x interface{}) bool {
	return x.(peer.ID).String() == m.val
}

func (m *PeerIDMatcher) String() string {
	return m.val
}

type PeerIDSliceMatcher struct {
	val []string
}

// NewPeerIDSliceMatcher matches given slice of peer.ID to a slice of strings
func NewPeerIDSliceMatcher(val ...string) *PeerIDSliceMatcher {
	return &PeerIDSliceMatcher{val: val}
}

func (m *PeerIDSliceMatcher) Matches(x interface{}) bool {
	got := make([]string, 0, len(m.val))
	for _, id := range x.([]peer.ID) {
		got = append(got, id.String())
	}
	return reflect.DeepEqual(m.val, got)
}

func (m *PeerIDSliceMatcher) String() string {
	return fmt.Sprintf("%v", m.val)
}

// TypeOfPeerID matches that given argument has the peer.ID type.
func TypeOfPeerID() gomock.Matcher {
	var peerIDType = reflect.TypeOf((*peer.ID)(nil)).Elem()
	return gomock.AssignableToTypeOf(peerIDType)
}
