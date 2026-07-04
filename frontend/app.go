package frontend

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"sort"

	"github.com/linckode/circl/blindsign/blindrsa"
	"github.com/maxence-charriere/go-app/v9/pkg/app"
	"ph-vote/api"
)

type MainApp struct {
	app.Compo
	Config             *api.ConfigRes
	EmailInput         string
	ShowEmailError     bool
	Message            string
	OTP                string
	IsVoting           bool
	VoteOption         string
	Token              []byte
	Signature          []byte
	AdminMode          bool
	AdminPwd           string
	AdminResults       map[string]int
	ShowResults        bool
	Results            map[string]int
	AdminConfirmClear  bool
	AdminClearPwd      string
	AdminClearSentence string
}

type deterministicReader struct {
	stream cipher.Stream
}

func newDeterministicReader(seed string) *deterministicReader {
	key := sha256.Sum256([]byte(seed))
	block, _ := aes.NewCipher(key[:])
	var iv [16]byte // 0 initialization vector
	stream := cipher.NewCTR(block, iv[:])
	return &deterministicReader{stream: stream}
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	r.stream.XORKeyStream(p, p)
	return len(p), nil
}

func (a *MainApp) OnMount(ctx app.Context) {
	app.Window().AddEventListener("click", func(ctx app.Context, e app.Event) {
		if a.ShowEmailError {
			a.ShowEmailError = false
			a.Update()
		}
	})

	u, _ := url.Parse(app.Window().URL().String())
	ctx.Async(func() {
		resp, err := http.Get(api.PathConfig)
		if err == nil {
			var conf api.ConfigRes
			if err := json.NewDecoder(resp.Body).Decode(&conf); err == nil {
				ctx.Dispatch(func(ctx app.Context) {
					a.Config = &conf
					app.Window().Get("document").Set("title", conf.Title)

					// Check magic link
					otp := u.Query().Get("otp")
					if otp != "" {
						a.Message = "Authenticating securely using RSA blind signatures..."
						a.OTP = otp
						a.Update()
						ctx.Async(a.performBlindSignAndShowVote(ctx, otp, conf.PublicKey))
					} else {
						restored := false
						ls := app.Window().Get("localStorage")
						if ls.Truthy() {
							tokStr := ls.Call("getItem", "vote_token").String()
							sigStr := ls.Call("getItem", "vote_sig").String()
							if tokStr != "" && sigStr != "" && tokStr != "null" && sigStr != "null" {
								tok, err1 := base64.StdEncoding.DecodeString(tokStr)
								sig, err2 := base64.StdEncoding.DecodeString(sigStr)
								if err1 == nil && err2 == nil {
									a.Token = tok
									a.Signature = sig
									a.IsVoting = true
									a.Message = "Session restored. Your vote is untraceable."
									a.Update()
									restored = true
								}
							}
						}
						if !restored {
							// No session and no OTP, simply show email form (default state)
							a.Message = ""
							a.Update()
						}
					}
				})
			}
			resp.Body.Close()
		}
	})
}

func (a *MainApp) onRequestLink(ctx app.Context, e app.Event) {
	e.PreventDefault()
	if a.EmailInput == "" {
		a.ShowEmailError = true
		a.Update()
		return
	}
	a.ShowEmailError = false
	a.Message = "Requesting magic link..."
	email := a.EmailInput

	ctx.Async(func() {
		reqData, _ := json.Marshal(api.MagicLinkReq{Email: email})
		resp, err := http.Post(api.PathRequestMagicLink, "application/json", bytes.NewBuffer(reqData))

		ctx.Dispatch(func(ctx app.Context) {
			if err != nil {
				a.Message = "Network error."
				return
			}

			if resp.Header.Get("Content-Type") == "application/json" {
				var resData map[string]bool
				json.NewDecoder(resp.Body).Decode(&resData)
				if resData["isAdmin"] {
					a.AdminMode = true
					a.EmailInput = ""
					a.Message = ""
					return
				}
			}

			if resp.StatusCode != 200 {
				a.Message = "Failed to request link. Invalid suffix or already requested."
			} else {
				a.Message = "Magic link sent! Check your inbox."
			}
		})
	})
}

func (a *MainApp) performBlindSignAndShowVote(ctx app.Context, otp string, pubKeyPEM []byte) func() {
	return func() {
		dr := newDeterministicReader(otp)

		// 1. Prepare raw token (the actual vote token)
		rawToken := make([]byte, 32)
		dr.Read(rawToken)

		// Parse Public Key
		block, _ := pem.Decode(pubKeyPEM)
		if block == nil {
			ctx.Dispatch(func(ctx app.Context) { a.Message = "Failed to parse server key" })
			return
		}
		pubKeyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			ctx.Dispatch(func(ctx app.Context) { a.Message = "Invalid public key format" })
			return
		}

		pubKey, ok := pubKeyAny.(*rsa.PublicKey)
		if !ok {
			ctx.Dispatch(func(ctx app.Context) { a.Message = "Public key is not RSA" })
			return
		}

		// 2. Blind the token
		client, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, pubKey)
		if err != nil {
			ctx.Dispatch(func(ctx app.Context) { a.Message = "Crypto init failed" })
			return
		}

		prepared, err := client.Prepare(dr, rawToken)
		if err != nil {
			return
		}

		blindedToken, state, err := client.Blind(dr, prepared)
		if err != nil {
			return
		}

		// 3. Send to server for signing
		reqData, _ := json.Marshal(api.SignTokenReq{OTP: otp, BlindedToken: blindedToken})
		resp, err := http.Post(api.PathSignToken, "application/json", bytes.NewBuffer(reqData))
		if err != nil {
			ctx.Dispatch(func(ctx app.Context) { a.Message = "Network error" })
			return
		}

		if resp.StatusCode == http.StatusConflict { // 409 Already Voted
			ls := app.Window().Get("localStorage")
			if ls.Truthy() {
				tokStr := ls.Call("getItem", "vote_token").String()
				sigStr := ls.Call("getItem", "vote_sig").String()
				if tokStr != "" && sigStr != "" && tokStr != "null" && sigStr != "null" {
					tok, err1 := base64.StdEncoding.DecodeString(tokStr)
					sig, err2 := base64.StdEncoding.DecodeString(sigStr)
					if err1 == nil && err2 == nil {
						ctx.Dispatch(func(ctx app.Context) {
							a.Token = tok
							a.Signature = sig
							a.IsVoting = true
							a.Message = "Session restored. Your vote is untraceable."
							app.Window().Get("history").Call("replaceState", nil, "", "/")
						})
						return
					}
				}
			}

			ctx.Dispatch(func(ctx app.Context) { a.Message = "Link has already been used on another device." })
			return
		}

		if resp.StatusCode != 200 {
			ctx.Dispatch(func(ctx app.Context) { a.Message = "Magic link invalid" })
			return
		}

		var res api.SignTokenRes
		json.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()

		// 4. Unblind signature
		signature, err := client.Finalize(state, res.BlindedSignature)
		if err != nil {
			ctx.Dispatch(func(ctx app.Context) { a.Message = "Failed to unblind signature" })
			return
		}

		// Success! Save token and signature, show voting UI.
		ctx.Dispatch(func(ctx app.Context) {
			a.Token = prepared
			a.Signature = signature

			ls := app.Window().Get("localStorage")
			if ls.Truthy() {
				ls.Call("setItem", "vote_token", base64.StdEncoding.EncodeToString(prepared))
				ls.Call("setItem", "vote_sig", base64.StdEncoding.EncodeToString(signature))
			}

			a.IsVoting = true
			a.Message = "Authenticated. Your vote is untraceable."
			app.Window().Get("history").Call("replaceState", nil, "", "/") // Hide OTP from URL
		})
	}
}

func (a *MainApp) onVote(ctx app.Context, e app.Event) {
	e.PreventDefault()
	if a.VoteOption == "" {
		return
	}

	a.Message = "Submitting vote anonymously..."
	ctx.Async(func() {
		reqData, _ := json.Marshal(api.VoteReq{
			Token:     a.Token,
			Signature: a.Signature,
			Option:    a.VoteOption,
		})
		resp, err := http.Post(api.PathVote, "application/json", bytes.NewBuffer(reqData))
		if err != nil || resp.StatusCode != 200 {
			ctx.Dispatch(func(ctx app.Context) {
				a.Message = "Vote failed. You may have already voted."
			})
			return
		}

		// Fetch results immediately
		resResp, err := http.Get(api.PathResults)
		if err == nil && resResp.StatusCode == 200 {
			var resData api.AdminRes
			json.NewDecoder(resResp.Body).Decode(&resData)
			resResp.Body.Close()
			ctx.Dispatch(func(ctx app.Context) {
				ls := app.Window().Get("localStorage")
				if ls.Truthy() {
					ls.Call("removeItem", "vote_token")
					ls.Call("removeItem", "vote_sig")
				}

				a.Results = resData.Votes
				a.ShowResults = true
				a.IsVoting = false
				a.Message = "Vote cast successfully!"
			})
		}
	})
}

func (a *MainApp) onAdminLogin(ctx app.Context, e app.Event) {
	e.PreventDefault()
	ctx.Async(func() {
		reqData, _ := json.Marshal(api.AdminReq{Password: a.AdminPwd})
		resp, err := http.Post(api.PathAdminVotes, "application/json", bytes.NewBuffer(reqData))
		if err == nil && resp.StatusCode == 200 {
			var res api.AdminRes
			json.NewDecoder(resp.Body).Decode(&res)
			ctx.Dispatch(func(ctx app.Context) {
				a.AdminResults = res.Votes
			})
		} else {
			ctx.Dispatch(func(ctx app.Context) { a.Message = "Invalid password" })
		}
	})
}

func (a *MainApp) onAdminClearDBRequest(ctx app.Context, e app.Event) {
	e.PreventDefault()
	a.AdminConfirmClear = true
	a.AdminClearPwd = ""
	a.AdminClearSentence = ""
}

func (a *MainApp) onAdminClearDBCancel(ctx app.Context, e app.Event) {
	e.PreventDefault()
	a.AdminConfirmClear = false
}

func (a *MainApp) onAdminClearDBConfirm(ctx app.Context, e app.Event) {
	e.PreventDefault()
	if a.AdminClearSentence != "I understand this deletes all data" {
		a.Message = "Confirmation sentence does not match exactly."
		a.Update()
		return
	}
	ctx.Async(func() {
		reqData, _ := json.Marshal(api.AdminReq{Password: a.AdminClearPwd})
		resp, err := http.Post(api.PathAdminClearDB, "application/json", bytes.NewBuffer(reqData))
		if err == nil && resp.StatusCode == 200 {
			ctx.Dispatch(func(ctx app.Context) {
				a.AdminResults = make(map[string]int)
				a.AdminConfirmClear = false
				a.Message = "Database cleared successfully."
			})
		} else {
			ctx.Dispatch(func(ctx app.Context) { a.Message = "Invalid password to clear DB" })
		}
	})
}

func (a *MainApp) Render() app.UI {
	if a.AdminMode {
		return a.renderAdmin()
	}

	var options []api.Candidate
	if a.Config != nil {
		options = a.Config.Options
	}

	return app.Div().Class("adwaita-window").Body(
		app.Div().Class("header-bar").Body(
			app.H1().Class("title").Text(a.getTitle()),
		),
		app.Div().Class("content").Body(
			app.If(a.ShowResults,
				app.H2().Text("Current Standings"),
				app.Ul().Class("results-list").Body(
					a.renderPublicResults(),
				),
				app.P().Class(a.msgClass("message")).Text(a.Message),
			).ElseIf(a.IsVoting,
				app.Form().OnSubmit(a.onVote).Body(
					app.P().Class(a.msgClass("dim-text")).Text(a.Message),
					app.Div().Class("boxed-list").Body(
						app.Range(options).Slice(func(i int) app.UI {
							opt := options[i]
							
							rowClass := "boxed-list-row"
							
							return app.Label().Class(rowClass).Body(
								app.Input().Type("radio").Name("voteOpt").Value(opt.ID).OnClick(func(ctx app.Context, e app.Event) {
									a.VoteOption = opt.ID
								}),
								app.Div().Class("candidate-content").Body(
									app.Raw(opt.HTML),
								),
							)
						}),
					),
					app.Button().Class("btn-primary").Type("submit").Text("Submit Vote"),
				),
			).Else(
				app.Form().OnSubmit(a.onRequestLink).NoValidate(true).Body(
					app.P().Class("dim-text").Text("Enter your email to receive an anonymous voting link."),
					app.Div().Class("input-container").Body(
						app.Input().
							Class(a.inputClass()).
							Type("email").
							Placeholder("Email address").
							Value(a.EmailInput).
							OnInput(func(ctx app.Context, e app.Event) {
								a.EmailInput = ctx.JSSrc().Get("value").String()
								if a.ShowEmailError {
									a.ShowEmailError = false
								}
								a.Update()
							}),
						app.If(a.ShowEmailError,
							app.Div().Class("adwaita-popover").Body(
								app.Span().Class("popover-icon-error").Text("!"),
								app.Span().Text("Please fill out this field."),
							),
						),
					),
					app.Button().Class("btn-primary").Type("submit").Text("Send Link").Style("margin-top", "12px"),
					app.P().Class(a.msgClass("message")).Text(a.Message),
				),
			),
		),
	)
}

func (a *MainApp) renderBarChart(results map[string]int) app.UI {
	// First, collect all options and their vote counts
	type CandidateVote struct {
		Name  string
		Votes int
	}

	var votes []CandidateVote

	// Ensure we include all candidates from config, even those with 0 votes
	if a.Config != nil {
		for _, opt := range a.Config.Options {
			count := 0
			if val, ok := results[opt.ID]; ok {
				count = val
			}
			votes = append(votes, CandidateVote{Name: opt.Name, Votes: count})
		}
	} else {
		// Fallback if config is not loaded but results exist
		for k, v := range results {
			votes = append(votes, CandidateVote{Name: k, Votes: v})
		}
	}

	// Sort by votes descending
	sort.SliceStable(votes, func(i, j int) bool {
		return votes[i].Votes > votes[j].Votes
	})

	// Find max votes for scaling the bar chart
	maxVotes := 0
	for _, v := range votes {
		if v.Votes > maxVotes {
			maxVotes = v.Votes
		}
	}

	var items []app.UI
	for _, v := range votes {
		percentage := 0.0
		if maxVotes > 0 {
			percentage = (float64(v.Votes) / float64(maxVotes)) * 100.0
		}

		items = append(items, app.Li().Class("result-item").Body(
			app.Div().Class("result-header").Body(
				app.Span().Class("result-name").Text(v.Name),
				app.Span().Class("result-votes").Text(fmt.Sprintf("%d votes", v.Votes)),
			),
			app.Div().Class("result-bar-container").Body(
				app.Div().Class("result-bar").Style("width", fmt.Sprintf("%.1f%%", percentage)),
			),
		))
	}
	if len(items) == 0 {
		items = append(items, app.Li().Text("No votes yet."))
	}
	return app.Div().Body(items...)
}

func (a *MainApp) renderPublicResults() app.UI {
	return a.renderBarChart(a.Results)
}

func (a *MainApp) renderAdmin() app.UI {
	return app.Div().Body(
		app.Div().Class("adwaita-window").Body(
			app.Div().Class("header-bar").Body(
				app.H1().Class("title").Text("Admin Dashboard"),
			),
			app.Div().Class("content").Body(
				app.If(a.AdminResults != nil,
					app.H2().Text("Results"),
					app.Ul().Class("results-list").Body(
						a.renderResults(),
					),
					app.Div().Style("margin-top", "30px").Body(
						app.H3().Text("Danger Zone"),
						app.Button().Class("btn-destructive").Text("Clear Database").OnClick(a.onAdminClearDBRequest),
					),
					app.P().Class(a.msgClass("message")).Text(a.Message),
				).Else(
					app.Form().OnSubmit(a.onAdminLogin).NoValidate(true).Body(
						app.Input().Class("input-box").Type("password").Placeholder("Admin Password").Value(a.AdminPwd).OnInput(a.ValueTo(&a.AdminPwd)),
						app.Button().Class("btn-primary").Type("submit").Text("Login").Style("margin-top", "12px"),
						app.P().Class(a.msgClass("message")).Text(a.Message),
					),
				),
			),
		),
		app.If(a.AdminConfirmClear,
			app.Div().Class("modal-overlay").Body(
				app.Div().Class("adwaita-dialog").Body(
					app.Form().OnSubmit(a.onAdminClearDBConfirm).NoValidate(true).Body(
						app.Div().Class("dialog-content").Body(
							app.H2().Class("dialog-title").Text("Clear Database?"),
							app.P().Class("dialog-body").Text("This will permanently delete all votes and used tokens."),
							app.Input().Class("input-box").Type("password").Placeholder("Admin Password").Value(a.AdminClearPwd).OnInput(a.ValueTo(&a.AdminClearPwd)),
							app.P().Class("dim-text").Style("font-size", "13px").Text("Type 'I understand this deletes all data' to confirm:"),
							app.Input().Class("input-box").Type("text").Placeholder("I understand this deletes all data").Value(a.AdminClearSentence).OnInput(a.ValueTo(&a.AdminClearSentence)),
							app.If(a.Message != "",
								app.P().Class("error-text").Text(a.Message),
							),
						),
						app.Div().Class("dialog-buttons").Body(
							app.Button().Type("button").Text("Cancel").OnClick(a.onAdminClearDBCancel),
							app.Button().Type("submit").Class("destructive-action").Text("Clear"),
						),
					),
				),
			),
		),
	)
}

func (a *MainApp) renderResults() app.UI {
	return a.renderBarChart(a.AdminResults)
}

func isErrorMsg(msg string) bool {
	switch msg {
	case "Failed to request link. Invalid suffix or already requested.",
		"Network error.",
		"Failed to parse server key",
		"Invalid public key format",
		"Public key is not RSA",
		"Crypto init failed",
		"Network error",
		"You have already voted! Here are the current standings.",
		"Magic link invalid",
		"Failed to unblind signature",
		"Vote failed. You may have already voted.",
		"Invalid password",
		"Confirmation sentence does not match exactly.",
		"Invalid password to clear DB":
		return true
	}
	return false
}

func (a *MainApp) msgClass(defaultClass string) string {
	if isErrorMsg(a.Message) {
		return "error-text"
	}
	return defaultClass
}

func (a *MainApp) inputClass() string {
	if a.ShowEmailError {
		return "input-box error"
	}
	return "input-box"
}

func (a *MainApp) getTitle() string {
	if a.Config != nil {
		return a.Config.Title
	}
	return "Ph-Vote"
}
