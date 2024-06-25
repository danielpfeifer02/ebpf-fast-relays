package main

import (
	"os"
	"strconv"

	fyne "fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func change_sender_data_specs() {

	a := app.New()
	w := a.NewWindow("Sender specifications")
	w.SetFixedSize(true)
	w.Resize(fyne.Size{Width: 600, Height: 400})

	// Default values.
	defaultPath := "../../../video/example.mp4"
	defaultMaxKeyFrame := "2"
	defaultMinKeyFrame := "0"

	// Filepath Entry.
	filepathInfoText := widget.NewLabel("Enter a filepath for the video file")
	filepath := widget.NewEntry()
	filepath.SetPlaceHolder(defaultPath)

	// Max Key Frame Distance Entry.
	maxKeyFrameInfoText := widget.NewLabel("Enter the maximum interval between key-frames (i-frames)")
	maxKeyFrame := widget.NewEntry()
	maxKeyFrame.SetPlaceHolder(defaultMaxKeyFrame)

	// Min Key Frame Distance Entry.
	minKeyFrameInfoText := widget.NewLabel("Enter the minimum interval between key-frames (i-frames)")
	minKeyFrame := widget.NewEntry()
	minKeyFrame.SetPlaceHolder(defaultMinKeyFrame)

	// Output Text Field.
	outputText := widget.NewLabel("")

	// Submit Button.
	submitButton := widget.NewButton("Submit", func() {
		fp := filepath.Text
		maxDist := maxKeyFrame.Text
		minDist := minKeyFrame.Text

		if fp == "" {
			fp = defaultPath
		}
		if maxDist == "" {
			maxDist = defaultMaxKeyFrame
		}
		if minDist == "" {
			minDist = defaultMinKeyFrame
		}

		maxDistInt, err1 := strconv.Atoi(maxDist)
		minDistInt, err2 := strconv.Atoi(minDist)
		if err1 != nil || err2 != nil {
			outputText.SetText("Please fill in valid values!")
			// Set back to default values.
			filepath.SetText(defaultPath)
			maxKeyFrame.SetText(defaultMaxKeyFrame)
			minKeyFrame.SetText(defaultMinKeyFrame)
			return
		}

		// Check if fp is a valid filepath, maxDist and minDist are integers.
		if !isValidFilepath(fp) {
			outputText.SetText("Please fill in valid values!")
			// Set back to default values.
			filepath.SetText(defaultPath)
			maxKeyFrame.SetText(defaultMaxKeyFrame)
			minKeyFrame.SetText(defaultMinKeyFrame)
			return
		} else {
			sender_specs.FilePath = fp
			sender_specs.KeyFrameMaxDist = uint32(maxDistInt)
			sender_specs.KeyFrameMinDist = uint32(minDistInt)

			// If all is valid, close the window.
			w.Close()
		}

	})

	// Allow pressing Enter to submit.
	w.Canvas().SetOnTypedKey(func(key *fyne.KeyEvent) {
		if key.Name == fyne.KeyReturn || key.Name == fyne.KeyEnter {
			submitButton.Tapped(&fyne.PointEvent{})
		} else if key.Name == fyne.KeyUp {
			txt := maxKeyFrame.Text
			if txt == "" {
				txt = defaultMaxKeyFrame
			}
			maxDist, _ := strconv.Atoi(txt)
			maxKeyFrame.SetText(strconv.Itoa(maxDist + 1))
		} else if key.Name == fyne.KeyDown {
			txt := maxKeyFrame.Text
			if txt == "" {
				txt = defaultMinKeyFrame
			}
			maxDist, _ := strconv.Atoi(txt)
			maxDist = max(maxDist-1, 0)
			maxKeyFrame.SetText(strconv.Itoa(maxDist))
		} else if key.Name == fyne.KeyRight {
			txt := minKeyFrame.Text
			if txt == "" {
				txt = defaultMinKeyFrame
			}
			minDist, _ := strconv.Atoi(txt)
			minKeyFrame.SetText(strconv.Itoa(minDist + 1))
		} else if key.Name == fyne.KeyLeft {
			txt := minKeyFrame.Text
			if txt == "" {
				txt = defaultMinKeyFrame
			}
			minDist, _ := strconv.Atoi(txt)
			minDist = max(minDist-1, 0)
			minKeyFrame.SetText(strconv.Itoa(minDist))
		} else if key.Name == fyne.KeyEscape {
			w.Close()
		}
	})

	// Create a form container.
	form := container.NewVBox(
		filepathInfoText,
		filepath,
		maxKeyFrameInfoText,
		maxKeyFrame,
		minKeyFrameInfoText,
		minKeyFrame,
		submitButton,
		outputText,
	)

	// Set the form as the window content.
	w.SetContent(form)

	// Show the window.
	w.ShowAndRun()
}

func isValidFilepath(fp string) bool { // TODO: Implement
	// Check if the file exists.
	_, err := os.Stat(fp)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	// Some other error.
	return false
}
