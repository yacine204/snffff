package cli

import (
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func Tui() {

    go SniffLoop()

	tv := tview.NewTextView()
	tv.SetDynamicColors(true)
	tv.SetBorder(true)
	tv.SetTextColor(tcell.ColorWhite)
    tv.SetScrollable(true)

	right := tview.NewBox().SetBorder(true)

	flex := tview.NewFlex().
		AddItem(tv, 0, 2, true).
		AddItem(right, 0, 1, false)

	app := tview.NewApplication().SetRoot(flex, true)

	go func() {
		for idx := range Notify{
            PacketMutex.Lock()
            p := Packet[idx]
            PacketMutex.Unlock()

            s := p.Header.S_MAC[:]
            d := p.Header.S_MAC
            
            line := fmt.Sprintf("[%d] s=%x d=%x\n", idx, s, d)
			app.QueueUpdateDraw(func() {
                fmt.Fprint(tv, line)
			})
		}
	}()

	if err := app.Run(); err != nil {
		panic(err)
	}
}
