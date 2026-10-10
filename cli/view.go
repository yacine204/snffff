package cli

import (
	"fmt"
	"os"
	"packet_sniffer/internal"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func generateLineHeader(eth *internal.ETH, idx int, masked bool) string{		
	    s := eth.Header.S_MAC[:]
        d := eth.Header.S_MAC
        protocol := eth.Inner_Protocol

        s_ip, d_ip:= eth.Inner.IpToString(masked)

        line := fmt.Sprintf("[%d] [blue]src mac=%x[-] [yellow]dest mac=%x[-] [green]src ip=%s[-] [orange]dest ip=%s\n[-] Protocol: %s", idx, s, d, s_ip, d_ip, protocol)
		return line
}

func Tui(masked bool) {

    go SniffLoop()

	utv := tview.NewTextView()
	utv.SetDynamicColors(true)
	utv.SetScrollable(true)
	utv.SetBorder(true)
	utv.SetTitle("L3 Layer")

	ltv := tview.NewTextView()
	ltv.SetDynamicColors(true)
	ltv.SetScrollable(true)
	ltv.SetBorder(true)
	ltv.SetTitle("L4 Layer")

    tb:= tview.NewTable()
    tb.SetBorder(true)
    tb.SetSelectable(true, false)
	tb.SetTitle("Packets")

	rflex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(utv, 0, 1, true).
		AddItem(ltv, 0, 1, true)
	rflex.SetBorder(true)

	flex := tview.NewFlex().
		AddItem(tb, 0, 2, true).
		AddItem(rflex, 0, 1, false)

	app := tview.NewApplication().SetRoot(flex, true)


	tb.SetSelectionChangedFunc(func(row, column int) {
		PacketMutex.Lock()
		if row>= len(Packet){
			PacketMutex.Unlock()
			return
		}

		p := Packet[row]
		PacketMutex.Unlock()
		l3text, l4text := p.Inner.ToString(true)
		utv.SetText(l3text)
		ltv.SetText(l4text)
	})
	

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {

		// select between rflex and tb
		// when rflex selected select lower or upper
		
		if event.Key() == tcell.KeyEnter{
			switch{
			case tb.HasFocus():
				app.SetFocus(rflex)
				return nil
			case utv.HasFocus():
				app.SetFocus(utv)
				return nil
			case ltv.HasFocus():
				app.SetFocus(ltv)
				return nil
			}
		}

		if event.Key() == tcell.KeyESC{
			switch{
			case tb.HasFocus():
				app.Stop()
				os.Exit(0)
				return nil
			case flex.HasFocus():
				app.SetFocus(tb)
				return nil
			case utv.HasFocus():
				app.SetFocus(rflex)
				return nil
			case ltv.HasFocus():
				app.SetFocus(rflex)
				return nil
			}
		}

		if event.Key() == tcell.KeyTab {
			switch {
			case utv.HasFocus():
				app.SetFocus(ltv)
				return nil
			case ltv.HasFocus():
				app.SetFocus(utv)
				return nil
        }
    }

		
		return event
	})

	go func() {
		for idx := range Notify{
            PacketMutex.Lock()
            p := Packet[idx]
            PacketMutex.Unlock()

            line := generateLineHeader(&p, idx, masked)
			
			app.QueueUpdateDraw(func() {
                tc := tview.NewTableCell(line)
                tb.SetCell(idx,0,tc)
			})
			
		}
	}()

	if err := app.Run(); err != nil {
		panic(err)
	}
}
