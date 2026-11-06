package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/wuling/xdp-forward-panel/internal/store"
)

const SessionTTL = 24 * time.Hour
const CookieName = "xfp_session"

type Service struct {
	store *store.Store
}

func New(s *store.Store) *Service { return &Service{store: s} }

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func RandomPassword(n int) (string, error) {
	if n < 12 {
		n = 16
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out), nil
}

func (s *Service) BootstrapAdmin(username string) (plain string, err error) {
	plain, err = RandomPassword(16)
	if err != nil {
		return "", err
	}
	hash, err := HashPassword(plain)
	if err != nil {
		return "", err
	}
	if err := s.store.EnsureAdmin(username, hash); err != nil {
		return "", err
	}
	// If user already existed, EnsureAdmin no-ops — detect by checking we just created?
	// Caller should only print password when freshly installed.
	return plain, nil
}

func (s *Service) EnsureFreshInstall(username string) (created bool, plain string, err error) {
	_, _, err = s.store.GetUser()
	if err == nil {
		return false, "", nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, "", err
	}
	plain, err = RandomPassword(16)
	if err != nil {
		return false, "", err
	}
	hash, err := HashPassword(plain)
	if err != nil {
		return false, "", err
	}
	if err := s.store.EnsureAdmin(username, hash); err != nil {
		return false, "", err
	}
	return true, plain, nil
}

func (s *Service) Login(username, password string) (token string, err error) {
	u, hash, err := s.store.GetUser()
	if err != nil {
		return "", fmt.Errorf("invalid credentials")
	}
	if u != username {
		return "", fmt.Errorf("invalid credentials")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", fmt.Errorf("invalid credentials")
	}
	token, err = randomToken(32)
	if err != nil {
		return "", err
	}
	if err := s.store.CreateSession(token, SessionTTL); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) Valid(token string) bool {
	ok, err := s.store.ValidSession(token)
	return err == nil && ok
}

func (s *Service) Logout(token string) error {
	return s.store.DeleteSession(token)
}

func (s *Service) ChangePassword(oldPW, newPW string) error {
	_, hash, err := s.store.GetUser()
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPW)) != nil {
		return fmt.Errorf("当前密码错误")
	}
	nh, err := HashPassword(newPW)
	if err != nil {
		return err
	}
	return s.store.UpdatePassword(nh)
}

func (s *Service) SetUsername(username string) error {
	if username == "" {
		return fmt.Errorf("用户名不能为空")
	}
	return s.store.UpdateUsername(username)
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
