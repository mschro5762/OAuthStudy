package users

import (
	"bytes"
	"context"
	"errors"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"testing"

	"go.uber.org/zap"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
)

type userRepositoryFake struct {
	CreateFunc         func(context.Context, User) error
	RetrieveFunc       func(context.Context, uuid.UUID) (User, error)
	RetrieveByNameFunc func(context.Context, string) (User, error)
	UpdateFunc         func(context.Context, User) error
	DeleteFunc         func(context.Context, uuid.UUID) error
}

func (repo *userRepositoryFake) Create(ctx context.Context, user User) error {
	if repo.CreateFunc != nil {
		return repo.CreateFunc(ctx, user)
	}

	return nil
}

func (repo *userRepositoryFake) Retrieve(ctx context.Context, id uuid.UUID) (User, error) {
	if repo.RetrieveFunc != nil {
		return repo.RetrieveFunc(ctx, id)
	}

	return User{}, nil
}

func (repo *userRepositoryFake) RetrieveByName(ctx context.Context, name string) (User, error) {
	if repo.RetrieveByNameFunc != nil {
		return repo.RetrieveByNameFunc(ctx, name)
	}

	return User{}, nil
}

func (repo *userRepositoryFake) Update(ctx context.Context, user User) error {
	if repo.UpdateFunc != nil {
		return repo.UpdateFunc(ctx, user)
	}

	return nil
}

func (repo *userRepositoryFake) Delete(ctx context.Context, id uuid.UUID) error {
	if repo.DeleteFunc != nil {
		return repo.DeleteFunc(ctx, id)
	}

	return nil
}

func TestUserService_NewUserService_RepoNil_ReturnsError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	_, err := NewUserService(ctx, nil)

	if err == nil {
		t.Fail()
	}
}

func TestUserService_NewUserService_RepoNil_ReturnsNilService(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	svc, _ := NewUserService(ctx, nil)

	if svc != nil {
		t.Fail()
	}
}

func TestUserService_NewUserService_HappyPath_ReturnsService(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	repo := &userRepositoryFake{}

	svc, _ := NewUserService(ctx, repo)

	if svc == nil {
		t.Fail()
	}
}

func TestUserService_NewUserService_HappyPath_ReturnsNilError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	repo := &userRepositoryFake{}

	_, err := NewUserService(ctx, repo)

	if err != nil {
		t.Fail()
	}
}

func TestUserService_NewUserService_HappyPath_PopulatesRepo(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	repo := &userRepositoryFake{}

	svc, _ := NewUserService(ctx, repo)

	if svc.repo != repo {
		t.Fail()
	}
}

func TestUserService_RegisterUser_HappyPath_ReturnsUser(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)
	repo := &userRepositoryFake{}
	svc, _ := NewUserService(ctx, repo)

	userName := "testuser"
	passwordClearText := "password123"

	user, _ := svc.RegisterUser(ctx, userName, []byte(passwordClearText))

	if user.ID == uuid.Nil ||
		user.Name != userName ||
		bcrypt.CompareHashAndPassword(user.Password, []byte(passwordClearText)) != nil {
		t.Fail()
	}
}

func TestUserService_RegisterUser_HappyPath_ReturnsNilError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)
	repo := &userRepositoryFake{}
	svc, _ := NewUserService(ctx, repo)

	userName := "testuser"
	passwordClearText := "password123"

	_, err := svc.RegisterUser(ctx, userName, []byte(passwordClearText))

	if err != nil {
		t.Fail()
	}
}

func TestUserService_RegisterUser_HappyPath_CreatesUserInRepo(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	var actualUser User
	repo := &userRepositoryFake{
		CreateFunc: func(ctx context.Context, user User) error {
			actualUser = user
			return nil
		},
	}

	svc, _ := NewUserService(ctx, repo)

	userName := "testuser"
	passwordClearText := "password123"

	expectedUser, _ := svc.RegisterUser(ctx, userName, []byte(passwordClearText))

	if actualUser.ID != expectedUser.ID ||
		actualUser.Name != expectedUser.Name ||
		!bytes.Equal(expectedUser.Password, actualUser.Password) {
		t.Fail()
	}
}

func TestUserService_RegisterUser_HappyPath_CallsRepoOnlyOnce(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	callCount := 0
	repo := &userRepositoryFake{
		CreateFunc: func(ctx context.Context, user User) error {
			callCount++
			return nil
		},
	}

	svc, _ := NewUserService(ctx, repo)

	userName := "testuser"
	passwordClearText := "password123"

	_, _ = svc.RegisterUser(ctx, userName, []byte(passwordClearText))

	if callCount != 1 {
		t.Fail()
	}
}

func TestUserService_RegisterUser_RepoReturnsError_ReturnsError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	expectedErr := errors.New("test error")

	repo := &userRepositoryFake{
		CreateFunc: func(ctx context.Context, user User) error {
			return expectedErr
		},
	}

	svc, _ := NewUserService(ctx, repo)

	userName := "testuser"
	passwordClearText := "password123"

	_, actualErr := svc.RegisterUser(ctx, userName, []byte(passwordClearText))

	if actualErr != expectedErr {
		t.Fail()
	}
}

func TestUserService_GetUser_HappyPath_ReturnsUser(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	passwordClearText := "password123"
	hashedPassword, _ := hashPassword([]byte(passwordClearText))

	expectedUser := User{
		ID:       uuid.New(),
		Name:     "testuser",
		Password: hashedPassword,
	}

	repo := &userRepositoryFake{
		RetrieveByNameFunc: func(ctx context.Context, userName string) (User, error) {
			return expectedUser, nil
		},
	}

	svc, _ := NewUserService(ctx, repo)

	actualUser, _ := svc.GetUser(ctx, expectedUser.Name)

	if actualUser.ID != expectedUser.ID {
		t.Fail()
	}

}

func TestUserService_GetUser_HappyPath_ReturnsNilError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	repo := &userRepositoryFake{}

	svc, _ := NewUserService(ctx, repo)

	_, err := svc.GetUser(ctx, "foo")

	if err != nil {
		t.Fail()
	}

}

func TestUserService_GetUser_RepositoryError_ReturnsZeroUser(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	zeroUser := User{}

	repo := &userRepositoryFake{
		RetrieveByNameFunc: func(ctx context.Context, userName string) (User, error) {
			return User{}, errors.New("test error")
		},
	}

	svc, _ := NewUserService(ctx, repo)

	actualUser, _ := svc.GetUser(ctx, "foo")

	if actualUser.ID != zeroUser.ID ||
		actualUser.Name != zeroUser.Name ||
		!bytes.Equal(actualUser.Password, zeroUser.Password) {
		t.Fail()
	}

}

func TestUserService_GetUser_RepositoryError_ReturnsError(t *testing.T) {
	ctx := contexthelper.NewContextWithLogger(zap.NewNop())

	repo := &userRepositoryFake{
		RetrieveByNameFunc: func(ctx context.Context, userName string) (User, error) {
			return User{}, errors.New("test error")
		},
	}

	svc, _ := NewUserService(ctx, repo)

	_, err := svc.GetUser(ctx, "foo")

	if err == nil {
		t.Fail()
	}

}

func TestUserService_ValidatePassword_PasswordsMatch_ReturnsTrue(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	passwordClearText := "password123"
	hashedPassword, _ := hashPassword([]byte(passwordClearText))

	user := User{
		ID:       uuid.New(),
		Name:     "testuser",
		Password: hashedPassword,
	}

	repo := &userRepositoryFake{
		RetrieveByNameFunc: func(ctx context.Context, userName string) (User, error) {
			return user, nil
		},
	}

	svc, _ := NewUserService(ctx, repo)

	passwordMatched, _ := svc.ValidatePassword(ctx, user, []byte(passwordClearText))

	if !passwordMatched {
		t.Fail()
	}
}

func TestUserService_ValidatePassword_PasswordsMatch_ReturnsNilError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	passwordClearText := "password123"
	hashedPassword, _ := hashPassword([]byte(passwordClearText))

	user := User{
		ID:       uuid.New(),
		Name:     "testuser",
		Password: hashedPassword,
	}

	repo := &userRepositoryFake{
		RetrieveByNameFunc: func(ctx context.Context, userName string) (User, error) {
			return user, nil
		},
	}

	svc, _ := NewUserService(ctx, repo)

	_, err := svc.ValidatePassword(ctx, user, []byte(passwordClearText))

	if err != nil {
		t.Fail()
	}
}

func TestUserService_ValidatePassword_PasswordsDoNotMatch_Returnsfalse(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	passwordClearText := "password123"
	hashedPassword, _ := hashPassword([]byte(passwordClearText))

	user := User{
		ID:       uuid.New(),
		Name:     "testuser",
		Password: hashedPassword,
	}

	repo := &userRepositoryFake{
		RetrieveByNameFunc: func(ctx context.Context, userName string) (User, error) {
			return user, nil
		},
	}

	svc, _ := NewUserService(ctx, repo)

	passwordMatched, _ := svc.ValidatePassword(ctx, user, []byte("badpassword"))

	if passwordMatched {
		t.Fail()
	}
}

func TestUserService_ValidatePassword_PasswordsDoNotMatch_ReturnsNilError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	passwordClearText := "password123"
	hashedPassword, _ := hashPassword([]byte(passwordClearText))

	user := User{
		ID:       uuid.New(),
		Name:     "testuser",
		Password: hashedPassword,
	}

	repo := &userRepositoryFake{
		RetrieveByNameFunc: func(ctx context.Context, userName string) (User, error) {
			return user, nil
		},
	}

	svc, _ := NewUserService(ctx, repo)

	_, err := svc.ValidatePassword(ctx, user, []byte("badpassword"))

	if err != nil {
		t.Fail()
	}
}

func TestUserService_ValidatePassword_BcryptReturnsError_ReturnsError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	passwordClearText := "password123"
	hashedPassword, _ := hashPassword([]byte(passwordClearText))

	user := User{
		ID:   uuid.New(),
		Name: "testuser",
		// Bcrypt generates hashes >=59 bytes
		Password: hashedPassword[:3],
	}

	repo := &userRepositoryFake{
		RetrieveByNameFunc: func(ctx context.Context, userName string) (User, error) {
			return user, nil
		},
	}

	svc, _ := NewUserService(ctx, repo)

	_, err := svc.ValidatePassword(ctx, user, []byte(passwordClearText))

	if err == nil {
		t.Fail()
	}
}

func TestUserService_ValidatePassword_BcryptReturnsError_Returnsfalse(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	ctx = contexthelper.AddLoggertoContext(ctx, logger)

	passwordClearText := "password123"
	hashedPassword, _ := hashPassword([]byte(passwordClearText))

	user := User{
		ID:   uuid.New(),
		Name: "testuser",
		// Bcrypt generates hashes >=59 bytes
		Password: hashedPassword[:3],
	}

	repo := &userRepositoryFake{
		RetrieveByNameFunc: func(ctx context.Context, userName string) (User, error) {
			return user, nil
		},
	}

	svc, _ := NewUserService(ctx, repo)

	passwordMatched, _ := svc.ValidatePassword(ctx, user, []byte(passwordClearText))

	if passwordMatched {
		t.Fail()
	}
}
