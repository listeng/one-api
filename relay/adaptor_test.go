package relay

import (
	"one-api/relay/apitype"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGetAdaptor(t *testing.T) {
	Convey("get adaptor", t, func() {
		for i := 0; i < apitype.Dummy; i++ {
			a := GetAdaptor(i)
			So(a, ShouldNotBeNil)
		}
	})
}
