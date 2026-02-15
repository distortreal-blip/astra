package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Theme from Figma SVG: dark blue gradient background, white text, blue accent.
type cosmicTheme struct {
	base fyne.Theme
}

var _ fyne.Theme = (*cosmicTheme)(nil)

func newCosmicTheme() fyne.Theme {
	return &cosmicTheme{base: theme.DefaultTheme()}
}

// Colors from SVG: gradient #162033 (top) -> #0C1220 (bottom), accent #009DFF, green #008E6D
var (
	figmaBgTop    = color.NRGBA{R: 0x16, G: 0x20, B: 0x33, A: 0xff} // #162033
	figmaBgBottom = color.NRGBA{R: 0x0c, G: 0x12, B: 0x20, A: 0xff} // #0C1220
	figmaAccent   = color.NRGBA{R: 0x00, G: 0x9d, B: 0xff, A: 0xff} // #009DFF
	figmaGreen    = color.NRGBA{R: 0x00, G: 0x8e, B: 0x6d, A: 0xff} // #008E6D
	figmaWhite    = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	figmaMuted    = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0x57} // ~34% opacity from SVG
)

func (t *cosmicTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return figmaBgBottom
	case theme.ColorNameButton:
		return figmaAccent
	case theme.ColorNameDisabled:
		return figmaMuted
	case theme.ColorNameForeground:
		return figmaWhite
	case theme.ColorNameInputBackground:
		return figmaBgTop
	case theme.ColorNamePlaceHolder:
		return figmaMuted
	case theme.ColorNamePrimary:
		return figmaAccent
	case theme.ColorNameHover:
		return figmaAccent
	case theme.ColorNameFocus:
		return figmaAccent
	case theme.ColorNameScrollBar:
		return figmaBgTop
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 0x40}
	default:
		return t.base.Color(name, variant)
	}
}

func (t *cosmicTheme) Font(style fyne.TextStyle) fyne.Resource {
	return t.base.Font(style)
}

func (t *cosmicTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.base.Icon(name)
}

func (t *cosmicTheme) Size(name fyne.ThemeSizeName) float32 {
	if name == theme.SizeNamePadding {
		return 12
	}
	return t.base.Size(name)
}
