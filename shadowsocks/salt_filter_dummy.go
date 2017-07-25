// +build no_salt_filter

package shadowsocks

type DummySaltFilter struct{}

func (f *DummySaltFilter) Contains([]byte) bool {
	return false
}

func (f *DummySaltFilter) Add([]byte) {}

func (f *DummySaltFilter) Clean() {}

func init() {
	saltFilter = &DummySaltFilter{}
}
