package users

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/google/uuid"
)

// UserFileRepository File repository for User objects
type UserFileRepository struct {
	filePath string
}

// NewFileRepository Creates a new UserFileRepository
// Returns an error if the given path is empty
func NewFileRepository(filePath string) (*UserFileRepository, error) {
	if strings.TrimSpace(filePath) == "" {
		return nil, errors.New("filePath empty")
	}

	newRepo := UserFileRepository{
		filePath: filePath,
	}

	return &newRepo, nil
}

// Create Creates a User in the repository.
// Returns an error if there is already a User with the given ID.
func (repo *UserFileRepository) Create(ctx context.Context, user User) error {
	users := repo.readFile(ctx)

	for _, c := range users {
		if c.ID == user.ID {
			return errors.New("Unable to create existent user with ID " + user.ID.String())
		}
	}

	users = append(users, user)

	err := repo.saveFile(ctx, users)
	if err != nil {
		return err
	}

	return nil
}

// Retrieve Retrieves a User with the given ID from the repository.
// Returns an error if the given ID is not found.
func (repo *UserFileRepository) Retrieve(ctx context.Context, id uuid.UUID) (User, error) {
	users := repo.readFile(ctx)

	for _, c := range users {
		if c.ID == id {
			return c, nil
		}
	}

	return User{}, errors.New("Unknown user ID" + id.String())
}

// RetrieveByName Retrieves a User with the given name from the repository.
// Returns an error if the given ID is not found.
func (repo *UserFileRepository) RetrieveByName(ctx context.Context, name string) (User, error) {
	users := repo.readFile(ctx)

	for _, c := range users {
		if c.Name == name {
			return c, nil
		}
	}

	return User{}, errors.New("Unknown user name " + name)
}

// Update Updates a user in the repository.
// Returns an error if the user does not already exist.
func (repo *UserFileRepository) Update(ctx context.Context, user User) error {
	users := repo.readFile(ctx)

	for i, c := range users {
		if c.ID == user.ID {
			users[i] = user
			err := repo.saveFile(ctx, users)
			if err != nil {
				return err
			}
			return nil
		}
	}

	return errors.New("Unknown user ID" + user.ID.String())
}

// Delete Removes a user from the repository.
// Returns an error if the ID does not exist in the repository.
func (repo *UserFileRepository) Delete(ctx context.Context, id uuid.UUID) error {
	users := repo.readFile(ctx)

	for i, c := range users {
		if c.ID == id {
			users = append(users[:i], users[i+1:]...)
			err := repo.saveFile(ctx, users)
			if err != nil {
				return err
			}
			return nil
		}
	}

	return errors.New("Unknown user ID" + id.String())
}

func (repo *UserFileRepository) readFile(ctx context.Context) []User {
	jsonBytes, err := ioutil.ReadFile(repo.filePath)
	if err != nil {
		return make([]User, 0)
	}

	var users []User
	if json.Unmarshal(jsonBytes, &users) != nil {
		return make([]User, 0)
	}

	return users
}

func (repo *UserFileRepository) saveFile(ctx context.Context, users []User) error {
	b, err := json.Marshal(users)
	if err != nil {
		return err
	}

	if ioutil.WriteFile(repo.filePath, b, 0644) != nil {
		return err
	}

	return nil
}
