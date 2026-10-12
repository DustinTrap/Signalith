package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// cmdSettings shows or removes the changes made on the Settings page. It
// is the way back when a change there locks people out: reset the
// setting here, then restart Signalith.
func cmdSettings(args []string) error {
	const use = "usage: signalith settings list [-c file]\n       signalith settings reset [-c file] [key...]   (no key: every change made on the page)"
	if len(args) == 0 || (args[0] != "list" && args[0] != "reset") {
		return errors.New(use)
	}
	fs := flag.NewFlagSet("settings "+args[0], flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args[1:])
	file, err := config.SettingsFileFor(*path)
	if err != nil {
		return err
	}
	page, readErr := config.ReadPageSettings(file)
	if args[0] == "list" {
		if readErr != nil {
			return fmt.Errorf("%v; remove it with: signalith settings reset", readErr)
		}
		if page.Empty() {
			fmt.Printf("Nothing was changed on the Settings page (%s).\n", file)
			return nil
		}
		fmt.Printf("Changed on the Settings page (%s):\n", file)
		for _, key := range page.Keys() {
			e := page.Settings[key]
			value := "(hidden)"
			if e.Secret == nil {
				var v any
				if e.Value.Decode(&v) == nil {
					value = fmt.Sprint(v)
				}
			}
			fmt.Printf("  %-34s %-28s by %s on %s\n", key, value, e.ChangedBy, e.ChangedAt.Local().Format("2006-01-02 15:04"))
		}
		return nil
	}
	keys := fs.Args()
	if len(keys) == 0 {
		if err := config.WritePageSettings(file, &config.PageSettings{}); err != nil {
			return err
		}
		fmt.Printf("Removed every change made on the Settings page (%s).\n", file)
		fmt.Println("Restart Signalith to use signalith.yaml alone.")
		return nil
	}
	if readErr != nil {
		return fmt.Errorf("%v; remove every change with: signalith settings reset", readErr)
	}
	for _, key := range keys {
		if _, ok := config.Lookup(key); !ok {
			return fmt.Errorf("%s is not a setting on the Settings page; see signalith settings list", key)
		}
	}
	var removed []string
	for _, key := range keys {
		if page.Remove(key) {
			removed = append(removed, key)
		}
	}
	if len(removed) == 0 {
		fmt.Println("None of these were changed on the Settings page; nothing to reset.")
		return nil
	}
	if err := config.WritePageSettings(file, page); err != nil {
		return err
	}
	fmt.Printf("Reset %s; signalith.yaml or the default applies again.\n", strings.Join(removed, ", "))
	fmt.Println("Restart Signalith to apply it.")
	return nil
}
