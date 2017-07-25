// +build !no_salt_filter

package shadowsocks

import "github.com/tylertreat/BoomFilters"

var sbf = boom.NewDefaultStableBloomFilter(10000000, 0.000001)

type SBFSaltFilter struct{}

func (f *SBFSaltFilter) Contains(salt []byte) bool {
	return sbf.Test(salt)
}

func (f *SBFSaltFilter) Add(salt []byte) {
	sbf.Add(salt)
}

func (f *SBFSaltFilter) Clean() {
	// stable bloom filter has no need to be cleaned regularly
}

func init() {
	saltFilter = WrapSyncSaltFilter(&SBFSaltFilter{})
}
