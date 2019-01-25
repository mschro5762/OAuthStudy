package users

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/logging"
)

// IUserService Abstraction for the UserService struct
type IUserService interface {
	RegisterUser(ctx context.Context, name string, passwordClearText []byte) (User, error)
	GetUser(ctx context.Context, name string) (User, error)
	ValidatePassword(ctx context.Context, user User, clearText []byte) (bool, error)
}

// UserService The service dealing with User actions
type UserService struct {
	repo IUserRepository
}

// NewUserService Constructs a new UserService object
func NewUserService(ctx context.Context, repo IUserRepository) (*UserService, error) {
	if repo == nil {
		return nil, errors.New("Nil argument: repo")
	}

	newSvc := UserService{
		repo: repo,
	}

	return &newSvc, nil
}

// RegisterUser Creates a user int the system
func (srv *UserService) RegisterUser(ctx context.Context, name string, passwordClearText []byte) (User, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	newUser := User{
		ID:   uuid.New(),
		Name: name,
	}

	logger.Info("Registering new user",
		zap.String(logging.FieldClientID, newUser.ID.String()),
		zap.String("userName", newUser.Name))

	hashedPassword, err := hashPassword(passwordClearText)
	if err != nil {
		logger.Error("Error hashing password",
			zap.Error(err))
		return User{}, err
	}

	newUser.Password = hashedPassword

	err = srv.repo.Create(ctx, newUser)
	if err != nil {
		logger.Error("Unable to save new user",
			zap.Error(err))
		return User{}, err
	}

	return newUser, nil
}

// GetUser Gets a user
func (srv *UserService) GetUser(ctx context.Context, name string) (User, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	user, err := srv.repo.RetrieveByName(ctx, name)
	if err != nil {
		logger.Info("Error finding user",
			zap.Error(err))
		return User{}, err
	}

	return user, nil
}

// ValidatePassword Evaluates the supplied clearText password with the stored hashed password.
func (srv *UserService) ValidatePassword(ctx context.Context, user User, clearText []byte) (bool, error) {
	logger := contexthelper.LoggerFromContext(ctx)

	err := bcrypt.CompareHashAndPassword(user.Password, clearText)
	if err != nil {
		logger.Info("Password compare failure",
			zap.Error(err))
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}

		return false, err
	}

	logger.Info("Password compare success")

	return true, nil
}

func hashPassword(clearText []byte) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword(clearText, 12)
	if err != nil {
		return nil, err
	}

	return hash, nil
}
