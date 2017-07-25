package shadowsocks

import "time"

type SaltFilter interface {
	Contains(salt []byte) bool
	Add(salt []byte)
	Clean()
}

var saltFilter SaltFilter

type SyncSaltFilter struct {
	SaltFilter
	add   chan []byte
	query chan []byte
	res   chan bool
}

func (f *SyncSaltFilter) run(t time.Duration) {
	after := time.After(t)
	for {
		select {
		case salt := <-f.query:
			f.res <- f.SaltFilter.Contains(salt)
		case salt := <-f.add:
			f.SaltFilter.Add(salt)
		case <-after:
			f.SaltFilter.Clean()
			after = time.After(t)
		}
	}
}

func (f *SyncSaltFilter) Contains(salt []byte) bool {
	f.query <- salt
	return <-f.res
}

func (f *SyncSaltFilter) Add(salt []byte) {
	f.add <- salt
}

func (f *SyncSaltFilter) Clean() {
	panic("SyncSaltFilter.Clean() should not be called")
}

func WrapSyncSaltFilter(f SaltFilter) (s *SyncSaltFilter) {
	s = &SyncSaltFilter{
		SaltFilter: f,
		add:        make(chan []byte),
		query:      make(chan []byte),
		res:        make(chan bool),
	}
	go s.run(30 * time.Minute)
	return
}
