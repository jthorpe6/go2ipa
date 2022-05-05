package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"github.com/radareorg/r2pipe-go"
	"github.com/thatisuday/commando"
)

type Info struct {
	Arch string
	BinType string
	Bits string
	Canary bool
	Class string
	Crypto bool
	Endian string
	Intrp string
	Lang string
	Os string
}

type Hashes struct {
	MD5 string
	SHA1 string
	SHA256 string
}

type Str struct {
	Vaddr int `json:"vaddr"`
	Paddr int `json:"paddr"`
	Ordinal int `json:"ordinal"`
	Size int `json:"size"`
	Length int `json:"length"`
	Section string `json:"section"`
	Type string `json:"type"`
	String string `json:"string"`
}

type Headers struct {
	Name string `json:"name"`
	Vaddr int `json:"vaddr"`
	Paddr int `json:"paddr"`
	Comment string `json:"comment"`
	Format string `json:"format"`
	//TODO Pf is nested
}

type Exports struct {
	Name string `json:"name"`
	Demname string `json:"demname"`
	Flagname string `json:"flagname"`
	Realname string `json:"realname"`
	Ordinal int `json:"ordinal"`
	Bind string `json:"bind"`
	Size int `json:"size"`
	Type string `json:"type"`
	Vaddr int `json:"vaddr"`
	Paddr int `json:"paddr"`
	IsImported bool `json:"is_imported"`
}

type Imports struct {
	Ordinal int
	Bind string
	Type string
	Name string
	Plt int
}

func getInfo(pipe *r2pipe.Pipe) Info {
	buf, err := pipe.Cmd("iIj")
	if err != nil {
		panic(err)
	}
	var info Info
	json.Unmarshal([]byte(buf), &info)
	return info
}

func getFileHashes(pipe *r2pipe.Pipe) Hashes {
	buf, err := pipe.Cmd("itj")
	if err != nil {
		panic(err)
	}

	var hashes Hashes

	json.Unmarshal([]byte(buf), &hashes)
	return hashes
}

func getHeaders(pipe *r2pipe.Pipe) []Headers {
	buf, err := pipe.Cmd("ihj")
	if err != nil {
		panic(err)
	}
	var headers []Headers
	json.Unmarshal([]byte(buf), &headers)
	return headers
}

func getExports(pipe *r2pipe.Pipe) []Exports {
	buf, err := pipe.Cmd("iEj")
	if err != nil {
		panic(err)
	}
	var exports []Exports
	json.Unmarshal([]byte(buf), &exports)
	return exports
}

func getImports(pipe *r2pipe.Pipe) []Imports {
	buf, err := pipe.Cmd("iij")
	if err != nil {
		panic(err)
	}

	var imports []Imports

	json.Unmarshal([]byte(buf), &imports)
	return imports
}

func getClasses(pipe *r2pipe.Pipe) string {
	buf, err := pipe.Cmd("icqq")
	if err != nil {
		panic(err)
	}
	return buf	
}

func getStrings(pipe *r2pipe.Pipe) []Str {
	buf, err := pipe.Cmd("izzzj")
	if err != nil {
		panic(err)
	}
	var strings []Str
	json.Unmarshal([]byte(buf), &strings)
	return strings
}

func main() {
	commando.
		SetExecutableName("go2ipa").
		SetVersion("v0.0.1").
		SetDescription(`
            ____  _             
  __ _  ___|___ \(_)_ __   __ _ 
 / _  |/ _ \ __) | | '_ \ / _  |
| (_| | (_) / __/| | |_) | (_| |
 \__, |\___/_____|_| .__/ \__,_|
 |___/             |_|          
 automated radare2 ipa analysis
`)

	commando.
		Register("info").
		SetShortDescription("show ipa information").
		SetDescription("show ipa information").
		AddArgument("ipa", "path to .ipa", "").
		AddFlag("lang,l", "display the language", commando.Bool, nil).
		AddFlag("arch,a", "display the arch", commando.Bool, nil).
		AddFlag("crypto,c", "ipa is encrypted? (bool)", commando.Bool, nil).
		SetAction(func(args map[string]commando.ArgValue,
			flags map[string]commando.FlagValue) {
			r2p, err := r2pipe.NewPipe("ipa://" + args["ipa"].Value)
			if err != nil {
				panic(err)
			}
			infoJson := getInfo(r2p)
			if flags["lang"].Value == true {
				fmt.Println(infoJson.Lang)
			}
			if flags["arch"].Value == true {
				fmt.Println(infoJson.Arch)
			}
			if flags["crypto"].Value == true {
				fmt.Println(infoJson.Crypto)
			}
		})

	commando.
		Register("hash").
		SetShortDescription("show ipa hash").
		SetDescription("show ipa hash").
		AddArgument("ipa", "path to .ipa", "").
		AddFlag("md5", "md5 hash", commando.Bool, nil).
		AddFlag("sha1", "sha1 hash", commando.Bool, nil).
		AddFlag("sha256", "sha265 hash", commando.Bool, nil).
		SetAction(func(args map[string]commando.ArgValue,
			flags map[string]commando.FlagValue) {
			r2p, err := r2pipe.NewPipe("ipa://" + args["ipa"].Value)
			if err != nil {
				panic(err)
			}
			fileHashJson := getFileHashes(r2p)
			if flags["md5"].Value == true {
				fmt.Println(fileHashJson.MD5)
			}
			if flags["sha1"].Value == true {
				fmt.Println(fileHashJson.SHA1)
			}
			if flags["sha254"].Value == true {
				fmt.Println(fileHashJson.SHA256)
			}
		})

	commando.
		Register("imports").
		SetShortDescription("show imported libraries").
		SetDescription("show imported libraries").
		AddArgument("ipa", "path to .ipa", "").
		AddFlag("ordinal,o", "", commando.Bool, nil).
		AddFlag("bind,b", "", commando.Bool, nil).
		AddFlag("type,t", "", commando.Bool, nil).
		AddFlag("plt,p", "", commando.Bool, nil).
		SetAction(func(args map[string]commando.ArgValue,
			flags map[string]commando.FlagValue) {
			r2p, err := r2pipe.NewPipe("ipa://" + args["ipa"].Value)
			if err != nil {
				panic(err)
			}
			imports := getImports(r2p)
			for _, imp := range(imports){
				if flags["ordinal"].Value == true {
					fmt.Println(imp.Name, ":", imp.Ordinal)
				}
				if flags["bind"].Value == true {
					fmt.Println(imp.Name, ":", imp.Bind)
				}
				if flags["type"].Value == true {
					fmt.Println(imp.Name, ":", imp.Type)
				}
				if flags["plt"].Value == true {
					fmt.Println(imp.Name, ":", imp.Plt)
				}
				if (flags["ordinal"].Value == false) &&
					(flags["bind"].Value == false) &&
					(flags["type"].Value == false) &&
					(flags["plt"].Value == false) {
					fmt.Println(imp.Name)
				}
			}
		})

	commando.
		Register("exports").
		SetShortDescription("show exported libraries").
		SetDescription("show exported libraries").
		AddArgument("ipa", "path to .ipa", "").
		AddFlag("ordinal,o", "", commando.Bool, nil).
		AddFlag("bind,b", "", commando.Bool, nil).
		AddFlag("size,s", "", commando.Bool, nil).
		AddFlag("type,t", "", commando.Bool, nil).
		AddFlag("vaddr,v", "", commando.Bool, nil).
		AddFlag("paddr,p", "", commando.Bool, nil).
		AddFlag("is_imported,i", "", commando.Bool, nil).
		SetAction(func(args map[string]commando.ArgValue,
			flags map[string]commando.FlagValue) {
			r2p, err := r2pipe.NewPipe("ipa://" + args["ipa"].Value)
			if err != nil {
				panic(err)
			}
			exports := getExports(r2p)
			for _, exp := range(exports){
				if flags["ordinal"].Value == true {
					fmt.Println(exp.Demname, ":", exp.Ordinal)
				}
				if flags["bind"].Value == true {
					fmt.Println(exp.Demname, ":", exp.Bind)
				}
				if flags["size"].Value == true {
					fmt.Println(exp.Demname, ":", exp.Size)
				}
				if flags["type"].Value == true {
					fmt.Println(exp.Demname, ":", exp.Type)
				}
				if flags["vaddr"].Value == true {
					fmt.Println(exp.Demname, ":", exp.Vaddr)
				}
				if flags["paddr"].Value == true {
					fmt.Println(exp.Demname, ":", exp.Paddr)
				}
				if flags["is_imported"].Value == true {
					fmt.Println(exp.Demname, ":", exp.IsImported)
				}
				if (flags["ordinal"].Value == false) &&
					(flags["bind"].Value == false) &&
					(flags["size"].Value == false) &&
					(flags["type"].Value == false) &&
					(flags["vaddr"].Value == false) &&
					(flags["paddr"].Value == false) &&
					(flags["is_imported"].Value == false){
					fmt.Println(exp.Demname)
				}
			}
		})

	commando.
		Register("headers").
		SetShortDescription("show headers").
		SetDescription("show headers (like jtool2)").
		AddArgument("ipa", "path to .ipa", "").
		AddFlag("vaddr,v", "", commando.Bool, nil).
		AddFlag("paddr,p", "", commando.Bool, nil).
		AddFlag("comment,c", "", commando.Bool, nil).
		AddFlag("format,f", "", commando.Bool, nil).
		SetAction(func(args map[string]commando.ArgValue,
			flags map[string]commando.FlagValue) {
			r2p, err := r2pipe.NewPipe("ipa://" + args["ipa"].Value)
			if err != nil {
				panic(err)
			}
			headders := getHeaders(r2p)
			for _, hea := range(headders){
				if flags["vaddr"].Value == true {
					fmt.Println(hea.Name, ":", hea.Vaddr)
				}
				if flags["paddr"].Value == true {
					fmt.Println(hea.Name, ":", hea.Paddr)
				}
				if flags["comment"].Value == true {
					fmt.Println(hea.Name, ":", hea.Comment)
				}
				if flags["format"].Value == true {
					fmt.Println(hea.Name, ":", hea.Format)
				}
				if (flags["vaddr"].Value == false) &&
					(flags["paddr"].Value == false) &&
					(flags["comment"].Value == false) &&
					(flags["format"].Value == false){
					fmt.Println(hea.Name)
				}
			}
		})
	
	commando.
		Register("classes").
		SetShortDescription("show non-system classnames").
		SetDescription("show non-system classnames").
		AddArgument("ipa", "path to .ipa", "").
		SetAction(func(args map[string]commando.ArgValue,
			flags map[string]commando.FlagValue) {
			r2p, err := r2pipe.NewPipe("ipa://" + args["ipa"].Value)
			if err != nil {
				panic(err)
			}

			classes := getClasses(r2p)
			fmt.Println(classes)
	})
	
	commando.
		Register("strings").
		SetShortDescription("show binary strings").
		SetDescription("show binary strings").
		AddArgument("ipa", "path to .ipa", "").
		AddFlag("web,w", "show only web strings", commando.Bool, nil).
		AddFlag("sql,s", "show only SQL strings", commando.Bool, nil).
		AddFlag("url,u", "show only URL schema strings", commando.Bool, nil).
		SetAction(func(args map[string]commando.ArgValue,
			flags map[string]commando.FlagValue) {
			r2p, err := r2pipe.NewPipe("ipa://" + args["ipa"].Value)
			if err != nil {
				panic(err)
			}
			binaryStrings := getStrings(r2p)
			for _, str := range(binaryStrings){
				if flags["web"].Value == true {
					if (strings.Contains(str.String, "http://")) ||
						(strings.Contains(str.String, "https://")) {
						fmt.Println(str.String)
					}
				}
				if flags["sql"].Value == true {
					statements := []string{"SELECT",
						"UPDATE",
						"INSERT",
						"DELETE",
						"AND",
						"LIKE"}
					for _, statement := range(statements){
						if strings.Contains(str.String, statement) {
							fmt.Println(str.String)
						}
					}
				}
				if flags["url"].Value == true {
					if (strings.Contains(str.String, "://")) &&
						(!strings.Contains(str.String, "http")) {
						fmt.Println(str.String)	
					}
				}
				//CONSIDER: adding other options from the Str struct
				if (flags["web"].Value == false) &&
					(flags["sql"].Value == false) &&
					(flags["url"].Value == false) {
					fmt.Println(str.String)
				}
			}
		})
	commando.Parse(nil)
}
