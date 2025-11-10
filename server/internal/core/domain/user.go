package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID         string    `json:"user_id"`
	UserName   string    `json:"user_name"`
	FirstName  string    `json:"first_name"`
	LastName   string    `json:"last_name"`
	Email      string    `json:"email"`
	Password   string    `json:"password"`
	IsActive   bool      `json:"is_active"`
	IsVerified bool      `json:"is_verified"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type UserWithRoles struct {
	User  User   `json:"user"`
	Roles []Role `json:"roles"`
}

type UserWithRole struct {
	User   User  `json:"user"`
	RoleID int32 `json:"role_id"`
}

type UserReq struct {
	UserName  string `json:"user_name"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

type UserResp struct {
	UserID    string `json:"user_id"`
	UserName  string `json:"user_name"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	IsActive  bool   `json:"is_active"`
}

func NewUserWithRole(newUser *UserReq, role RoleString) (*UserWithRole, error) {
	if newUser == nil {
		return nil, errors.New("user request cannot be nil")
	}

	roleID, err := getRoleID(role)
	if err != nil {
		return nil, err
	}

	return &UserWithRole{
		User: User{
			ID:         uuid.NewString(),
			UserName:   newUser.UserName,
			LastName:   newUser.LastName,
			Email:      newUser.Email,
			FirstName:  newUser.FirstName,
			Password:   "",
			IsActive:   true,
			IsVerified: false,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		RoleID: roleID,
	}, nil
}

func getRoleID(role RoleString) (int32, error) {
	switch role {
	case RoleAdmin:
		return RoleAdminID, nil
	case RoleDeveloper:
		return RoleDeveloperID, nil
	case RoleUser:
		return RoleUserID, nil
	default:
		return 0, errors.New("invalid role")
	}
}

func GetRoleString(roleID int32) RoleString {
	switch roleID {
	case RoleAdminID:
		return RoleAdmin
	case RoleDeveloperID:
		return RoleDeveloper
	case RoleUserID:
		return RoleUser
	default:
		return RoleUser
	}
}
