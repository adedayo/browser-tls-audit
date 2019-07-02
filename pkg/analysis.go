package model

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	chrome   = regexp.MustCompile(`Chrome/(\d{1,3}[.]\d{1,3})(?:[.]\d{1,3}){,3} Safari/\d{1,3}[.]\d{1,3}(?:[.]\d{1,3}){,3}$`)
	ff       = regexp.MustCompile(`Firefox/(\d{1,3}[.]\d{1,3}(?:[.]\d{1,3})?)$`)
	opr      = regexp.MustCompile(`OPR/(\d{1,3}[.]\d{1,3}[.]\d{1,4}[.]\d{1,3})$`)
	sfr      = regexp.MustCompile(`Safari/(\d{1,3}[.]\d{1,3}(?:[.]\d{1,3})?)$`)
	opr2     = regexp.MustCompile(`^Opera/\d{1,3}[.]\d{1,3}.*Version/(\d\d)[.].*`)
	ie       = regexp.MustCompile(`MSIE (\d{1,3}[.]\d{1,3})`)
	ie2      = regexp.MustCompile(`rv:(\d{1,3}[.]\d{1,3})\) like Gecko`)
	mobie    = regexp.MustCompile(`IEMobile/(\d{1,3}[.]\d{1,3})`)
	midori   = regexp.MustCompile(`Midori/(\d{1,3}[.]\d{1,3})$`)
	konq     = regexp.MustCompile(`Konqueror/(\d{1,3}[.]\d{1,3})$`)
	seamonk  = regexp.MustCompile(`SeaMonkey/(\d{1,3}[.]\d{1,3})(?:[.]\d{1,3})?$`)
	epiphany = regexp.MustCompile(`Epiphany/(\d[.])(?:\d{1,3}[.]\d{1,3})$`)
	iceape   = regexp.MustCompile(`Iceape/(\d[.]\d{1,3})(?:[.]\d{1,3})$`)
	gshot    = regexp.MustCompile(`GrapeshotCrawler/(\d{1,3}[.]\d{1,3})`)

	osSignatures = map[string]string{
		"Intel Mac OS X 10.14":         "Mac OS X (Mojave)",
		"Intel Mac OS X 10_14_":        "Mac OS X (Mojave)",
		"Intel Mac OS X 10.13":         "Mac OS X (High Sierra)",
		"Intel Mac OS X 10_13_":        "Mac OS X (High Sierra)",
		"Intel Mac OS X 10.12":         "Mac OS X (El Capitan)",
		"Intel Mac OS X 10_12_":        "Mac OS X (El Capitan)",
		"Intel Mac OS X 10.11":         "Mac OS X (Sierra)",
		"Intel Mac OS X 10_11_":        "Mac OS X (Sierra)",
		"Intel Mac OS X 10.10":         "Mac OS X (Yosemite)",
		"Intel Mac OS X 10_10_":        "Mac OS X (Yosemite)",
		"Intel Mac OS X 10.9":          "Mac OS X (Mavericks)",
		"Intel Mac OS X 10_9_":         "Mac OS X (Mavericks)",
		"Intel Mac OS X 10.8":          "Mac OS X (Mountain Lion)",
		"Intel Mac OS X 10_8_":         "Mac OS X (Mountain Lion)",
		"Intel Mac OS X 10.7":          "Mac OS X (Lion)",
		"Intel Mac OS X 10_7_":         "Mac OS X (Lion)",
		"Intel Mac OS X 10.6":          "Mac OS X (Snow Leopard)",
		"Intel Mac OS X 10_6_":         "Mac OS X (Snow Leopard)",
		"Macintosh; U; Intel Mac OS X": "Mac OS X",
		"Windows NT 10.0":              "Windows 10",
		"Windows NT 6.3":               "Windows 8.1",
		"Windows NT 6.2":               "Windows 8",
		"Windows NT 6.1":               "Windows 7",
		"Windows NT 5.2":               "Windows Server 2003",
		"Mobile; Windows Phone 8.1":    "Windows Phone 8.1",
		"CPU iPhone OS 11_4":           "iOS 11.4",
		"CPU iPhone OS 11_3":           "iOS 11.3",
		"CPU iPhone OS 11_2":           "iOS 11.2",
		"CPU iPhone OS 11_1":           "iOS 11.1",
		"CPU iPhone OS 11_0":           "iOS 11",
		"CPU iPhone OS 10_3":           "iOS 10.3",
		"CPU iPhone OS 9_3":            "iOS 9.3",
		"CPU iPhone OS 9_2":            "iOS 9.2",
		"CPU iPhone OS 9_1":            "iOS 9.1",
		"CPU iPhone OS 9_0_1":          "iOS 9",
		"iPad; CPU OS 12_1":            "iOS 12.1",
		"iPad; CPU OS 11_0":            "iOS 11",
		"iPad; CPU OS 11_2":            "iOS 11.2",
		"iPad; CPU OS 11_4":            "iOS 11.4",
		"iPad; CPU OS 11_3":            "iOS 11.3",
		"iPad; CPU OS 8_1":             "iOS 8.1",
		"CPU iPhone OS 12_1":           "iOS 12.1",
		"X11; Linux":                   "Linux",
		"X11; Ubuntu; Linux":           "Linux",
		"Linux i686":                   "Linux",
		"Linux; Android 9":             "Android 9",
		"Linux; Android 8.":            "Android 8",
		"Linux; Android 7.":            "Android 7",
		"Linux; Android 6.":            "Android 6",
		"Linux; Android 5.":            "Android 5",
		"Linux; Android 4.":            "Android 4",
		"Grapeshot":                    "Grapeshot",
		"Browsershots":                 "Browsershots",
	}
)

type browser struct {
	name, version, os string
}

func getBrowserVersionAndOS(ua string) (b browser, e error) {
	if os, err := getOS(ua); err == nil {
		b.os = os
	} else {
		return b, err
	}

	if br, ver, err := getBrowserAndVersion(ua); err == nil {
		b.name = br
		b.version = ver
		return b, nil
	}
	return b, fmt.Errorf("Unknown browser from user agent: %s", ua)
}

func getOS(ua string) (string, error) {
	for s, os := range osSignatures {
		if strings.Contains(ua, s) {
			return os, nil
		}
	}

	return "", fmt.Errorf("Unknown OS from user agent: %s", ua)
}

func getBrowserAndVersion(ua string) (string, string, error) {

	if matches := chrome.FindStringSubmatch(ua); len(matches) == 2 {
		return "Chrome", matches[1], nil
	}

	if matches := ff.FindStringSubmatch(ua); len(matches) == 2 {
		return "Firefox", matches[1], nil
	}

	if matches := sfr.FindStringSubmatch(ua); len(matches) == 2 {
		return "Safari", matches[1], nil
	}

	if matches := opr.FindStringSubmatch(ua); len(matches) == 2 {
		return "Opera", matches[1], nil
	}

	if matches := opr2.FindStringSubmatch(ua); len(matches) == 2 {
		return "Opera", matches[1], nil
	}

	if matches := ie.FindStringSubmatch(ua); len(matches) == 2 {
		return "IE", matches[1], nil
	}

	if matches := ie2.FindStringSubmatch(ua); len(matches) == 2 {
		return "IE", matches[1], nil
	}

	if matches := mobie.FindStringSubmatch(ua); len(matches) == 2 {
		return "IE Mobile", matches[1], nil
	}

	if matches := iceape.FindStringSubmatch(ua); len(matches) == 2 {
		return "Iceape", matches[1], nil
	}

	if strings.Contains(ua, "Browsershots") {
		return "Browsershots", "1", nil
	}

	if matches := midori.FindStringSubmatch(ua); len(matches) == 2 {
		return "Midori", matches[1], nil
	}

	if matches := konq.FindStringSubmatch(ua); len(matches) == 2 {
		return "Konqueror", matches[1], nil
	}

	if matches := seamonk.FindStringSubmatch(ua); len(matches) == 2 {
		return "SeaMonkey", matches[1], nil
	}

	if matches := epiphany.FindStringSubmatch(ua); len(matches) == 2 {
		return "Epiphany", matches[1], nil
	}

	if matches := gshot.FindStringSubmatch(ua); len(matches) == 2 {
		return "GrapeshotCrawler", matches[1], nil
	}

	if strings.Contains(ua, "WebKit") {
		return "WebKit", "0", nil
	}

	return "", "", fmt.Errorf("Unknown browser name or browser version from user agent: %s", ua)
}
