package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/mattermost/mattermost-server/v5/model"
)

func main() {
	Client := model.NewAPIv4Client("http://localhost:8065/")
	Client.Login("toto", "tototo")
	data, _ := hex.DecodeString("58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a")
	us := &model.UploadSession{
		ChannelId: "7wynam16o38tbfgegi1qjr53oy",
		Filename:  "eicar",
		FileSize:  int64(len(data)),
	}
	us, response := Client.CreateUpload(us)
	fmt.Printf("lol %s %#+v\n", us, response)
	info, err2 := Client.UploadData(us.Id, bytes.NewReader(data))
	fmt.Printf("lol %s %#+v\n", err2, info)
}
