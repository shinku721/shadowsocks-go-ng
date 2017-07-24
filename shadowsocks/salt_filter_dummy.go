// +build !salt_filter_bloom,!salt_filter_cuckoo,!salt_filter_simple

package shadowsocks

type DummySaltFilter struct {}

func (f *DummySaltFilter) Contains([]byte) bool {
  return false
}

func (f *DummySaltFilter) Add([]byte) {}

func init() {
  saltFilter = &DummySaltFilter{}
}
