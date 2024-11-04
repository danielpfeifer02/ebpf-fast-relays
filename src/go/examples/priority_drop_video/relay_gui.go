package main

import (
	"errors"
	"net"
	"strconv"

	"common.com/common"
	fyne "fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func create_relay_video_config_manager() {
	a := app.New()
	w := a.NewWindow("Video config manager")
	w.SetFixedSize(true)
	w.Resize(fyne.Size{Width: 600, Height: 400})

	// IP Address Entry
	ipAddressInfoText := widget.NewLabel("Enter the IP address and port of the connection you want to change the priority for")
	ipAddress := widget.NewEntry()
	ipAddress.SetPlaceHolder("Enter IP Address")

	// Port Number Entry
	portInfoText := widget.NewLabel("Enter the port number of the connection you want to change the priority for")
	portNumber := widget.NewEntry()
	portNumber.SetPlaceHolder("Enter Port Number")

	// Integer Value Entry
	prioInfoText := widget.NewLabel("Set the priority value you want to set")
	prioValue := widget.NewSlider(min_priority_slider, max_priority_slider)
	prioValue.Step = 1
	prioValue.SetValue(min_priority_slider)
	prioCurrentValue := widget.NewLabel(strconv.Itoa(min_priority_slider))
	prioInfoContainer := container.NewHBox(prioInfoText, prioCurrentValue)
	prioValue.OnChanged = func(val float64) {
		prioCurrentValue.SetText(strconv.Itoa(int(val)))
	}

	// Output Text Field
	outputText := widget.NewLabel("")

	// Checkbox to toggle IP and Port fields requirement
	checkBox := widget.NewCheck("Consider all connections", func(checked bool) {
		if checked {
			ipAddress.SetText("")
			portNumber.SetText("")
			ipAddress.Disable()
			portNumber.Disable()
		} else {
			ipAddress.Enable()
			portNumber.Enable()
		}
	})
	checkBox.SetChecked(true)

	// Submit Button
	submitButton := widget.NewButton("Submit", func() {
		ip := ipAddress.Text
		port := portNumber.Text
		prioVal_tmp := int(prioValue.Value)
		if prioVal_tmp < max(0, min_priority_slider) || prioVal_tmp > min(max_priority_slider, 1<<8-1) {
			outputText.SetText("Invalid priority value")
			return
		}
		prioVal := uint8(prioVal_tmp)

		if checkBox.Checked {

			err := setPriorityForAllConnections(prioVal)
			if err != nil {
				outputText.SetText(err.Error())
				return
			}
			outputText.SetText("Priority set for all connections")

		} else {
			// Check if IP and Port fields are filled
			if ip == "" || port == "" {
				outputText.SetText("Please fill in IP Address and Port")
				return
			}

			err := setPriorityForConnection(ip, port, prioVal)
			if err != nil {
				outputText.SetText(err.Error())
				return
			}

			// Reset fields after successful submission
			ipAddress.SetText("")
			portNumber.SetText("")
			outputText.SetText("Action successful")
		}
	})

	// Allow pressing Enter to submit
	w.Canvas().SetOnTypedKey(func(key *fyne.KeyEvent) {
		if key.Name == fyne.KeyReturn || key.Name == fyne.KeyEnter {
			submitButton.Tapped(&fyne.PointEvent{})
		} else if key.Name == fyne.KeyUp {
			prioValue.SetValue(min(max_priority_slider, prioValue.Value+1))
		} else if key.Name == fyne.KeyDown {
			prioValue.SetValue(max(min_priority_slider, prioValue.Value-1))
		} else if key.Name == fyne.KeyEscape {
			w.Close()
		}
	})

	// Create a form container
	form := container.NewVBox(
		checkBox,
		ipAddressInfoText,
		ipAddress,
		portInfoText,
		portNumber,
		prioInfoContainer,
		prioValue,
		submitButton,
		outputText,
	)

	// Set the form as the window content
	w.SetContent(form)

	// Show the window
	w.ShowAndRun()
}

func setPriorityForAllConnections(prioVal uint8) error {

	// TODO: will likely not be working if client_ids can be given back (e.g. when
	// TODO: a connection is retired)

	number_of_clients := 1 // TODO: get dynamically

	for i := 1; i <= number_of_clients; i++ {
		err := common.ChangePriorityDropLimit(uint32(i), uint8(prioVal))
		if err != nil {
			return err
		}
	}

	return nil
}

func setPriorityForConnection(ip_in, port_in string, prioVal uint8) error {
	ip := net.ParseIP(ip_in)
	if ip == nil {
		return errors.New(" Invalid IP address ")
	}
	port, err := strconv.Atoi(port_in)
	if err != nil {
		return errors.New(" Invalid port number ")
	}

	// Check that port is in the valid range
	if port < 0 || port >= 1<<16 {
		return errors.New(" Port number out of range ")
	}

	client_id, err := common.GetClientID(ip, uint16(port))
	if err != nil {
		return err
	}

	return common.ChangePriorityDropLimit(client_id, uint8(prioVal))
}
