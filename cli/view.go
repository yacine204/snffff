package cli

import (
	"fmt"
	"github.com/rivo/tview"
)

func Tui() {

    go SniffLoop()

    tb:= tview.NewTable()
    tb.SetBorder(true)
    tb.SetSelectable(true, false)


	// tv := tview.NewTextView()
	// tv.SetDynamicColors(true)
	// tv.SetBorder(true)
	// tv.SetTextColor(tcell.ColorWhite)
    // tv.SetScrollable(true)


	right := tview.NewBox().SetBorder(true)

	flex := tview.NewFlex().
		AddItem(tb, 0, 2, true).
		AddItem(right, 0, 1, false)

	app := tview.NewApplication().SetRoot(flex, true)

	go func() {
		for idx := range Notify{
            PacketMutex.Lock()
            p := Packet[idx]
            PacketMutex.Unlock()

            s := p.Header.S_MAC[:]
            d := p.Header.S_MAC

            s_ip, d_ip:= p.Inner.IpToString()

            line := fmt.Sprintf("[%d] src mac=%x dest mac=%x src ip=%s dest ip=%s\n", idx, s, d, s_ip, d_ip)
			app.QueueUpdateDraw(func() {
                // fmt.Fprint(tv, line)
                tc := tview.NewTableCell(line)
                tb.SetCell(idx,1,tc)
			})
		}
	}()

	if err := app.Run(); err != nil {
		panic(err)
	}
}
