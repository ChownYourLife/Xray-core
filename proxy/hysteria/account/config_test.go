package account_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/hysteria/account"
)

func TestValidatorRemovalCancelsDerivedRoutesOnlyForOwner(t *testing.T) {
	v := account.NewValidator()
	makeUser := func(email, auth string) *protocol.MemoryUser {
		a, err := (&account.Account{Auth: auth}).AsAccount()
		common.Must(err)
		u := &protocol.MemoryUser{Email: email, Account: a}
		common.Must(v.Add(u))
		return u
	}
	alice := makeUser("a@test", "27e2bd8b-8ad6-4d2a-b3cf-1a8a3a0fe2b1")
	bob := makeUser("b@test", "27e2bd8b-8ad6-4d2a-b3cf-1a8a3a0fe2b2")
	routed := v.Get("27e2bd8b-8ad6-ffff-b3cf-1a8a3a0fe2b1")
	if routed == nil || routed == alice {
		t.Fatal("route bytes did not derive an account")
	}
	routed.Cancel()
	if alice.Context().Err() != nil {
		t.Fatal("derived account canceled its owner")
	}
	common.Must(v.DelByEmail("a@test"))
	if routed.Context().Err() == nil {
		t.Fatal("removed user's routed account remained active")
	}
	if v.Get("27e2bd8b-8ad6-ffff-b3cf-1a8a3a0fe2b1") != nil {
		t.Fatal("removed user's alternate route still authenticates")
	}
	if bob.Context().Err() != nil || v.GetByEmail("b@test") != bob {
		t.Fatal("removal affected another user")
	}
	replacement := makeUser("a@test", "27e2bd8b-8ad6-4d2a-b3cf-1a8a3a0fe2b1")
	if replacement.Context().Err() != nil {
		t.Fatal("readded user inherited the removed owner's cancellation")
	}
}
