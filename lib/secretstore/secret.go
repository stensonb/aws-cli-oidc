package secretstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/stensonb/aws-cli-oidc/lib/config"
	"github.com/stensonb/aws-cli-oidc/lib/log"
	"github.com/stensonb/aws-cli-oidc/lib/types"
	"github.com/werf/lockgate"
	"github.com/werf/lockgate/pkg/file_locker"
	"github.com/zalando/go-keyring"
)

const DEFAULT_LOCK_TIMEOUT = 3 * time.Minute

var lockResource = config.AWS_CLI_OIDC
var secretService = config.AWS_CLI_OIDC
var secretUser = os.Getenv("USER")

type SecretStore struct {
	AWSCredentials map[string]string `json:"credentials"`
	locker         lockgate.Locker
	lockHandle     *lockgate.LockHandle
}

func NewSecretStore(ctx context.Context, lockDir string) (*SecretStore, error) {
	if lockDir == "" {
		lockDir = filepath.Join(os.TempDir(), fmt.Sprintf("%s-lock", config.AWS_CLI_OIDC))
	}

	locker, err := file_locker.NewFileLocker(lockDir)
	if err != nil {
		return nil, fmt.Errorf("can't setup file locker: %w", err)
	}

	ans := &SecretStore{
		AWSCredentials: make(map[string]string),
		locker:         locker,
	}

	if err := ans.Load(ctx); err != nil {
		return nil, err
	}

	return ans, nil
}

func (s *SecretStore) lock(ctx context.Context) error {
	acquired, lock, err := s.locker.Acquire(lockResource, lockgate.AcquireOptions{Shared: false, Timeout: DEFAULT_LOCK_TIMEOUT})
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !acquired {
		return fmt.Errorf("call to locker.Acquire returned without error, but acquired==false")
	}

	s.lockHandle = &lock

	return nil
}

// release the s.lockHandle, if we have one
func (s *SecretStore) unlock() error {
	if s.lockHandle != nil {
		return s.locker.Release(*s.lockHandle)
	}

	return nil
}

func (s *SecretStore) Load(ctx context.Context) error {

	// lockCtx, lockCancel := context.WithTimeout(ctx, DEFAULT_LOCK_TIMEOUT)
	// defer lockCancel()

	err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := s.unlock(); err != nil {
			log.Writeln("warning: failed to unlock")
		}
	}()

	// TODO: guard with context
	jsonStr, err := keyring.Get(secretService, secretUser)
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil
		}
		return fmt.Errorf("can't load secret due to unexpected error: %w", err)
	}
	if err := json.Unmarshal([]byte(jsonStr), &s); err != nil {
		return fmt.Errorf("can't umarshal data from loaded secret: %w", err)
	}

	// select {
	// case <-lockCtx.Done():
	// case <-didit:
	// }
	return nil
}

func (s *SecretStore) Save(ctx context.Context, roleArn string, cred string) error {
	err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := s.unlock(); err != nil {
			log.Writeln("warning: failed to unlock")
		}
	}()

	// TODO: guard via context
	// Load the latest credentials
	jsonStr, err := keyring.Get(secretService, secretUser)
	if err != nil {
		if err != keyring.ErrNotFound {
			return fmt.Errorf("can't load secret due to unexpected error: %v", err)
		}
	}
	if jsonStr != "" {
		if err := json.Unmarshal([]byte(jsonStr), &s); err != nil {
			return fmt.Errorf("can't load secret due to broken data: %v", err)
		}
	}

	// Add/Update credential
	s.AWSCredentials[roleArn] = cred

	// Save
	newJsonStr, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("can't marshal credentials: %w", err)
	}

	// TODO: guard with context?
	if err := keyring.Set(secretService, secretUser, string(newJsonStr)); err != nil {
		return fmt.Errorf("failed to save secret: %w", err)
	}

	return nil
}

func (s *SecretStore) AWSCredential(roleArn string) (*types.AWSCredentials, error) {
	jsonStr, ok := s.AWSCredentials[roleArn]
	if !ok {
		return nil, fmt.Errorf("not found the credential for %s", roleArn)
	}

	log.Writeln("Got credential from OS secret store for %s", roleArn)

	var cred types.AWSCredentials

	err := json.Unmarshal([]byte(jsonStr), &cred)
	if err != nil {
		return nil, fmt.Errorf("can't load secret due to the broken data: %w", err)
	}

	return &cred, nil
}

func (s *SecretStore) SaveAWSCredential(ctx context.Context, roleArn string, cred *types.AWSCredentials) error {
	jsonStr, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("can't save secret due to the broken data: %w", err)
	}

	if err := s.Save(ctx, roleArn, string(jsonStr)); err != nil {
		return err
	}

	return nil
}

func (s *SecretStore) Clear(ctx context.Context) error {
	err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := s.unlock(); err != nil {
			log.Writeln("warning: failed to unlock")
		}
	}()

	// TODO: guard with context
	return keyring.Delete(secretService, secretUser)
}
