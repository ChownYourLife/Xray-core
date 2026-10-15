package protocol

import (
	"context"
	"reflect"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
)

func (u *User) GetTypedAccount() (Account, error) {
	if u.GetAccount() == nil {
		return nil, errors.New("Account is missing")
	}

	rawAccount, err := u.Account.GetInstance()
	if err != nil {
		return nil, err
	}
	if asAccount, ok := rawAccount.(AsAccount); ok {
		return asAccount.AsAccount()
	}
	if account, ok := rawAccount.(Account); ok {
		return account, nil
	}
	return nil, errors.New("Unknown account type: ", u.Account.Type)
}

func (u *User) ToMemoryUser() (*MemoryUser, error) {
	account, err := u.GetTypedAccount()
	if err != nil {
		return nil, err
	}
	return &MemoryUser{
		Account: account,
		Email:   u.Email,
		Level:   u.Level,
	}, nil
}

func ToProtoUser(mu *MemoryUser) *User {
	if mu == nil {
		return nil
	}
	return &User{
		Account: serial.ToTypedMessage(mu.Account.ToProto()),
		Email:   mu.Email,
		Level:   mu.Level,
	}
}

// MemoryUser is a parsed form of User, to reduce number of parsing of Account proto.
type MemoryUser struct {
	// Account is the parsed account of the protocol.
	Account Account
	Email   string
	Level   uint32

	origin *MemoryUser
	once   sync.Once
	ctx    context.Context
	cancel context.CancelFunc
}

// Context is canceled when the owning user is removed.
func (u *MemoryUser) Context() context.Context {
	if u.origin != nil {
		return u.origin.Context()
	}
	u.once.Do(func() {
		u.ctx, u.cancel = context.WithCancel(context.Background())
	})
	return u.ctx
}

// Cancel ends the owning user's connections. Derived users do not own them.
func (u *MemoryUser) Cancel() {
	if u.origin == nil {
		u.Context()
		u.cancel()
	}
}

// Equal compares configuration, excluding runtime lifecycle state.
func (u *MemoryUser) Equal(v *MemoryUser) bool {
	if u == nil || v == nil {
		return u == v
	}
	return reflect.DeepEqual(u.Account, v.Account) && u.Email == v.Email && u.Level == v.Level
}

// Derive substitutes an account while retaining the owning user's lifecycle.
func (u *MemoryUser) Derive(account Account) *MemoryUser {
	return &MemoryUser{Account: account, Email: u.Email, Level: u.Level, origin: u}
}
