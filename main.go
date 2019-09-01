package main

import (
	"github.com/bwmarrin/discordgo"
)

const (
	BotToken = ""
)

func check(err error) {
	if err != nil {
		// TODO(hazebooth): better error handling
		panic(err)
	}
}

func main() {
	sesh, err := discordgo.New("Bot " + BotToken)
	check(err)
}

func CanFindModel(path string) bool {

}
