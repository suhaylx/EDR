package edr

import (
	"errors"
	"strings"
)

// stripSysmonClipboardDetail removes free-form, potentially sensitive clipboard
// content before the laboratory event enters storage, responses or detections.
// This is an ingestion safety net; the endpoint should never collect content.
func stripSysmonClipboardDetail(e *Event) error {
	if e.Source != "sysmon" || e.Platform != "windows" || e.SourceEventID != 24 {
		return nil
	}
	if e.Hash != "" || len(e.SourceRecordID) > 20 ||
		(e.SourceRecordID != "" && strings.Trim(e.SourceRecordID, "0123456789") != "") {
		return errors.New("clipboard metadata must not contain a hash or nonnumeric source record ID")
	}
	e.Detail = "Sysmon clipboard change observed; clipboard content not collected"
	return nil
}
