package crypto

type HashFake struct {
	WriteFunc     func(p []byte) (n int, err error)
	SumFunc       func(b []byte) []byte
	ResetFunc     func()
	SizeFunc      func() int
	BlockSizeFunc func() int
}

func (fake *HashFake) Write(p []byte) (n int, err error) {
	if fake.WriteFunc != nil {
		return fake.WriteFunc(p)
	}

	return 0, nil
}

func (fake *HashFake) Sum(b []byte) []byte {
	if fake.SumFunc != nil {
		return fake.SumFunc(b)
	}

	return make([]byte, 0, 0)
}

func (fake *HashFake) Reset() {
	if fake.ResetFunc != nil {
		fake.ResetFunc()
	}
}

func (fake *HashFake) Size() int {
	if fake.SizeFunc != nil {
		return fake.SizeFunc()
	}

	return 0
}

func (fake *HashFake) BlockSize() int {
	if fake.BlockSizeFunc != nil {
		return fake.BlockSizeFunc()
	}

	return 8
}
