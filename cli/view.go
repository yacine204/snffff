package cli

import (
	"fmt"
	"os"
	"packet_sniffer/internal"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func generateLineHeader(eth *internal.ETH, idx int, masked bool) string {
	if eth == nil || eth.Inner == nil {
		return fmt.Sprintf("[%d] (unparsed)", idx)
	}
	s := eth.Header.S_MAC[:]
	d := eth.Header.S_MAC

	s_ip, d_ip := eth.Inner.IpToString(masked)

	line := fmt.Sprintf("[%d] [blue]src mac=%x[-] [yellow]dest mac=%x[-] [green]src ip=%s[-] [orange]dest ip=%s\n[-] Protocol: %s", idx, s, d, s_ip, d_ip, string(eth.Inner.GetInnerProtocol()))
	return line
}

func flowIDSuggestions(query string) []string {
	q := strings.TrimSpace(query)
	if q == "" {
		return nil
	}

	PacketMutex.Lock()
	defer PacketMutex.Unlock()

	seen := map[string]struct{}{}
	matches := make([]string, 0)
	for _, packet := range Packet {
		if packet.Inner == nil {
			continue
		}
		flowID, ok := internal.FlowID(packet.Inner)
		if !ok {
			continue
		}
		if _, exists := seen[flowID]; exists {
			continue
		}
		seen[flowID] = struct{}{}
		if strings.Contains(flowID, q) {
			matches = append(matches, flowID)
		}
	}

	sort.Strings(matches)
	return matches
}

func rebuildFilteredPackets(query string) ([]internal.ETH, []int) {
	q := strings.TrimSpace(query)
	packets := make([]internal.ETH, 0)
	indexes := make([]int, 0)

	PacketMutex.Lock()
	defer PacketMutex.Unlock()
	for i, packet := range Packet {
		if packet.Inner == nil {
			continue
		}
		flowID, ok := internal.FlowID(packet.Inner)
		if !ok {
			continue
		}
		if q == "" || strings.Contains(flowID, q) {
			packets = append(packets, packet)
			indexes = append(indexes, i)
		}
	}
	return packets, indexes
}

func renderVisiblePacketsNow(tb *tview.Table, packets []internal.ETH, masked bool) {
	tb.Clear()
	for row, packet := range packets {
		if packet.Inner == nil {
			continue
		}
		line := generateLineHeader(&packet, row, masked)
		tb.SetCell(row, 0, tview.NewTableCell(line))
	}
}

func Tui(masked bool, demo bool) {
	if demo {
		go DemoSniffLoop()
	} else {
		go SniffLoop()
	}
	

	utv := tview.NewTextView()
	utv.SetDynamicColors(true)
	utv.SetScrollable(true)
	utv.SetBorder(true)

	ltv := tview.NewTextView()
	ltv.SetDynamicColors(true)
	ltv.SetScrollable(true)
	ltv.SetBorder(true)

	tb := tview.NewTable()
	tb.SetBorder(true)
	tb.SetSelectable(true, false)
	tb.SetTitle("Packets")

	reassemblyView := tview.NewTextView()
	reassemblyView.SetDynamicColors(true)
	reassemblyView.SetBorder(true)
	reassemblyView.SetScrollable(true)

	filter := tview.NewInputField()
	filter.SetBorder(true)

	lflex := tview.NewFlex().SetDirection(tview.FlexRow)
	lflex.SetBorder(true)
	lflex.AddItem(filter, 0, 1, true)
	lflex.AddItem(tb, 0, 12, true)

	rflex := tview.NewFlex().SetDirection(tview.FlexRow)
	rflex.AddItem(utv, 0, 1, true)
	rflex.AddItem(ltv, 0, 1, true)
	rflex.AddItem(reassemblyView, 0, 1, true)
	rflex.SetBorder(true)

	ltv.SetScrollable(true)

	var reassemblyViewVisible bool
	var currentFlowID string
	var visibleIdx []int
	var filterActive bool

	flex := tview.NewFlex().
		AddItem(lflex, 0, 2, true).
		AddItem(rflex, 0, 1, true)

	app := tview.NewApplication().SetRoot(flex, true)

	filter.SetAutocompleteFunc(func(currentText string) []string {
		return flowIDSuggestions(currentText)
	})

	applyFilter := func() {
		query := strings.TrimSpace(filter.GetText())
		packets, idxs := rebuildFilteredPackets(query)
		if query == "" {
			filterActive = false
			visibleIdx = nil
		} else {
			filterActive = true
			visibleIdx = idxs
		}
		renderVisiblePacketsNow(tb, packets, masked)
		tb.Select(0, 0)
	}

	filter.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}

		query := strings.TrimSpace(filter.GetText())
		if query == "" {
			applyFilter()
			return
		}

		suggestions := flowIDSuggestions(query)
		if len(suggestions) > 0 && suggestions[0] != query {
			filter.SetText(suggestions[0])
			query = suggestions[0]
		}

		applyFilter()

		for row, rawIdx := range visibleIdx {
			PacketMutex.Lock()
			if rawIdx < 0 || rawIdx >= len(Packet) {
				PacketMutex.Unlock()
				continue
			}
			p := Packet[rawIdx]
			PacketMutex.Unlock()
			if p.Inner == nil {
				continue
			}
			flowID, ok := internal.FlowID(p.Inner)
			if ok && flowID == query {
				tb.Select(row, 0)
				app.SetFocus(tb)
				return
			}
		}
	})

	filter.SetChangedFunc(func(text string) {
		applyFilter()
	})

	tb.SetSelectionChangedFunc(func(row, column int) {
		var realIdx int
		if filterActive {
			if row < 0 || row >= len(visibleIdx) {
				return
			}
			realIdx = visibleIdx[row]
		} else {
			realIdx = row
		}

		PacketMutex.Lock()
		if realIdx < 0 || realIdx >= len(Packet) {
			PacketMutex.Unlock()
			return
		}
		p := Packet[realIdx]
		PacketMutex.Unlock()
		if p.Inner == nil {
			return
		}

		l3text, l4text := p.Inner.ToString(true)
		utv.SetText(l3text)
		ltv.SetText(l4text)
		utv.SetTitle(string(p.Inner_Protocol))
		ltv.SetTitle(string(p.Inner.GetInnerProtocol()))

		isTCP := p.Inner.GetInnerProtocol() == internal.TCPProtocol
		if isTCP && !reassemblyViewVisible {
			reassemblyViewVisible = true
			rflex.ResizeItem(reassemblyView, 0, 1)

			flowId, _ := internal.FlowID(p.Inner)
			reassemblyView.SetTitle(flowId)
			data := internal.UpdatedTCPReassemblyByFlowId(flowId)
			reassemblyView.SetText(fmt.Sprintf("% x", data))
			currentFlowID = flowId
		} else if !isTCP && reassemblyViewVisible {
			reassemblyViewVisible = false
			rflex.ResizeItem(reassemblyView, 0, 0)
		}
	})

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEnter {
			switch {
			case tb.HasFocus():
				app.SetFocus(rflex)
				return nil
			case utv.HasFocus():
				app.SetFocus(utv)
				return nil
			case ltv.HasFocus():
				app.SetFocus(ltv)
				return nil
			case reassemblyView.HasFocus():
				app.SetFocus(reassemblyView)
				return nil
			}
		}

		if event.Key() == tcell.KeyESC {
			switch {
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
			case reassemblyView.HasFocus():
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
				app.SetFocus(reassemblyView)
				return nil
			case reassemblyView.HasFocus():
				app.SetFocus(utv)
				return nil
			case tb.HasFocus():
				app.SetFocus(filter)
				return nil
			case filter.HasFocus():
				app.SetFocus(tb)
				return nil
			}
		}
		return event
	})

	go func() {
		for idx := range Notify {
			app.QueueUpdateDraw(func() {
				if filterActive {
					return
				}
				PacketMutex.Lock()
				if idx < 0 || idx >= len(Packet) {
					PacketMutex.Unlock()
					return
				}
				p := Packet[idx]
				PacketMutex.Unlock()
				if p.Inner == nil {
					return
				}
				line := generateLineHeader(&p, idx, masked)
				tb.SetCell(idx, 0, tview.NewTableCell(line))
			})
		}
	}()

	go func() {
		for n := range internal.ReassembleNotified {
			app.QueueUpdateDraw(func() {
				if n.FlowId != currentFlowID {
					return
				}
				reassemblyView.SetText(fmt.Sprintf("% x", n.Data))
			})
		}
	}()

	if err := app.Run(); err != nil {
		panic(err)
	}
}