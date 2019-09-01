package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/go-redis/redis"
	"github.com/mb-14/gomarkov"
)

const (
	BotToken      = ""
	BotID         = "412776104978546688"
	RedisModelKey = "markov-models"
	ChainOrder    = 1
)

func check(err error) {
	if err != nil {
		// TODO(hazebooth): better error handling
		panic(err)
	}
}

type ChainIndex = map[string]*gomarkov.Chain

var (
	Redis           *redis.Client
	BannedGuilds    []string
	ConversationMap ChainIndex
)

func init() {
	inst := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})
	_, err := inst.Ping().Result()
	check(err)
	Redis = inst
	BannedGuilds = []string{"370161659408285697"}
	ConversationMap = make(ChainIndex)
}

type packedChainAndMember struct {
	chain    *gomarkov.Chain
	memberID string
}

func IsGuildBanned(guildID string) bool {
	for _, s := range BannedGuilds {
		if s == guildID {
			return true
		}
	}
	return false
	// return sort.SearchStrings(BannedGuilds, guildID) == -1
}

func messageCreate(sess *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == sess.State.User.ID {
		return
	}
	mentions := m.Mentions
	mentionCount := len(mentions)
	content := m.Content
	if strings.HasPrefix(content, "!pretend") {
		var victimID string
		if mentionCount == 1 {
			victimID = m.Mentions[0].ID
		} else {
			victimID = strings.Split(content, " ")[1]
		}
		response := GeneratePretendPhrase(victimID)
		fmt.Printf("Generated %q for %s\n", response, victimID)
		sess.ChannelMessageSend(m.ChannelID, response)
		return
	} else if strings.HasPrefix(content, "!conversation") {
		var victimID string
		if mentionCount == 1 {
			victimID = m.Mentions[0].ID
		} else {
			victimID = strings.Split(content, " ")[1]
		}
		response := StartConversation(m.Author.ID, victimID)
		sess.ChannelMessageSend(m.ChannelID, response)
		return
	} else if strings.HasPrefix(content, "!seance") {
		var victimID string
		if mentionCount == 1 {
			victimID = m.Mentions[0].ID
		} else {
			victimID = strings.Split(content, " ")[1]
		}
		response := StartConversation(m.GuildID, victimID)
		sess.ChannelMessageSend(m.ChannelID, response)
		return
	} else if strings.HasPrefix(content, "!retrain") {
		sess.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Started retraining on guild %s…", m.GuildID))
		// elapsed := BuildModel(sess)
		start := time.Now()
		BuildModelForChannelSimple(sess, m.GuildID)
		end := time.Now()
		sess.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Rebuilt model in %f seconds", end.Sub(start).Seconds()))
	} else if strings.HasPrefix(content, "!quit") {
		if _, ok := ConversationMap[m.GuildID]; ok {
			delete(ConversationMap, m.GuildID)
		} else {
			delete(ConversationMap, m.Author.ID)
		}
		sess.ChannelMessageSend(m.ChannelID, "Ended any open conversations you had.")
		return
	} else if strings.HasPrefix(content, "!help") {
		sess.ChannelMessageSend(m.ChannelID, "```!{conversation|seance|pretend} <@mention/id> -- conversation replies without having to tag a user, seance is a guild wide conversation, pretend returns one response\n!quit -- stops current seance / conversation\n!retrain -- retrains the model for the given guild```")
		return
	}
	if chain, ok := ConversationMap[m.Author.ID]; ok {
		sess.ChannelMessageSend(m.ChannelID, GenerateMessage(chain))
		return
	}
	if chain, ok := ConversationMap[m.GuildID]; ok {
		sess.ChannelMessageSend(m.ChannelID, GenerateMessage(chain))
		return
	}
}

func StartConversation(requesterID, memberID string) string {
	chain, err := GetChainForUser(memberID)
	if err != nil {
		return fmt.Sprintf("Failed to start conversation: %s", memberID)
	}
	ConversationMap[requesterID] = chain
	return fmt.Sprintf("Started conversation with ***<@%s>***.", memberID)
}

func GetChainForUser(memberID string) (*gomarkov.Chain, error) {
	jsonBytes, err := Redis.Get(memberID).Bytes()
	if err != nil {
		return nil, err
	}
	var obj gomarkov.Chain
	err = json.Unmarshal(jsonBytes, &obj)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

func GenerateMessage(chain *gomarkov.Chain) string {
	tokens := []string{gomarkov.StartToken}
	for tokens[len(tokens)-1] != gomarkov.EndToken {
		next, _ := chain.Generate(tokens[(len(tokens) - 1):])
		// fmt.Printf("%+v, %q\n", tokens, next)
		tokens = append(tokens, next)
	}
	return strings.Join(tokens[1:len(tokens)-1], " ")
}

func GeneratePretendPhrase(memberID string) string {
	var response string
	chain, err := GetChainForUser(memberID)
	if err != nil {
		fmt.Printf("Encountered error generating response: %q\n", err.Error())
		response = err.Error()
	} else {
		response = GenerateMessage(chain)
	}
	return response
}

func main() {
	sesh, err := discordgo.New("Bot " + BotToken)
	check(err)

	sesh.AddHandler(messageCreate)
	err = sesh.Open()
	check(err)

	if !CanFindModel() {
		fmt.Println("Could not find model, building…")
		elapsedSeconds := BuildModel(sesh)
		fmt.Printf("Built & Saved model in %d seconds\n", elapsedSeconds)
	}

	fmt.Println("Press CTRL-C to quit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc

	// Cleanly close down the Discord session.
	sesh.Close()
}

func IsValidMessageForChain(content string) bool {
	trimmed := strings.TrimSpace(content)
	return trimmed != "" && !IsBotCommand(trimmed) && !IsURL(trimmed) && !IsTooShort(trimmed)
}

func IsURL(str string) bool {
	_, err := url.ParseRequestURI(str)
	if err != nil {
		return false
	} else {
		return true
	}
}

func IsTooShort(str string) bool {
	return len([]rune(str)) < 4
}

func IsBotCommand(str string) bool {
	return strings.HasPrefix(str, ".") || strings.HasPrefix(str, "'") || str == "vc enable" || strings.HasPrefix("!", str) || strings.HasPrefix("?", str)
}

func HasURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// Remove links
func SanitizeMessageContent(content string) string {
	return strings.TrimSpace(content)
}

func BuildModel(sess *discordgo.Session) int {
	start := time.Now()
	state := sess.State

	state.RLock()
	var wg sync.WaitGroup
	mm := NewModelMap()
	for _, guild := range state.Guilds {
		guildID := guild.ID
		if IsGuildBanned(guildID) {
			fmt.Printf("%s is banned, skipping…\n", guildID)
			continue
		}
		wg.Add(1)
		go BuildModelForChannel(sess, guildID, &mm, &wg)
	}
	state.RUnlock()
	wg.Wait()
	fmt.Println()
	SaveModelToRedis(&mm)
	end := time.Now()
	diff := end.Sub(start).Seconds()
	return int(diff)
}

type ModelMap struct {
	Index ChainIndex
	sync.Mutex
}

func NewModelMap() ModelMap {
	return ModelMap{
		Index: make(ChainIndex, 0),
	}
}

func (m *ModelMap) Put(key string, value *gomarkov.Chain) {
	m.Lock()
	m.Index[key] = value
	m.Unlock()
}

func (m *ModelMap) Iterate(f func(string, *gomarkov.Chain)) {
	for key, value := range m.Index {
		f(key, value)
	}
}

func (m *ModelMap) Get(key string) (*gomarkov.Chain, bool) {
	val, ok := m.Index[key]
	return val, ok
}

func BuildModelForChannelSimple(sess *discordgo.Session, guildID string) {
	mm := NewModelMap()
	BuildModelForChannel(sess, guildID, &mm, nil)
	SaveModelToRedis(&mm)
}

func BuildModelForChannel(sess *discordgo.Session, guildID string, modelMap *ModelMap, wg *sync.WaitGroup) {
	channels, err := sess.GuildChannels(guildID)
	check(err)
	processed := 0
	for _, channel := range channels {
		channelID := channel.ID
		hasMessages := true
		lastMessage := ""
		for hasMessages {
			messages, err := sess.ChannelMessages(channelID, 100, lastMessage, "", "")
			if err != nil {
				break
			}
			check(err)
			msgCount := len(messages)
			switch msgCount {
			case 0:
				hasMessages = false
			default:
				processed += msgCount
				fmt.Printf("\r\033[K%s %d…", channel.Name, processed)
				for messageIdx, message := range messages {
					author := message.Author
					authorID := author.ID
					var chain *gomarkov.Chain
					if foundChain, ok := modelMap.Get(authorID); ok {
						chain = foundChain
					} else {
						chain = gomarkov.NewChain(ChainOrder)
						modelMap.Put(authorID, chain)
					}
					sanitized := SanitizeMessageContent(message.Content)
					if IsValidMessageForChain(sanitized) {
						// extra url test
						// TODO(hazebooth): simplify / remove
						words := strings.Split(sanitized, " ")
						n := 0
						for _, x := range words {
							if !IsURL(x) {
								words[n] = x
								n++
							}
						}
						words = words[:n]
						chain.Add(words)
					}
					if messageIdx == msgCount-1 {
						lastMessage = message.ID
					}
				}
			}
		}
	}
	if wg != nil {
		wg.Done()
	}
}

// MemberHasPermission checks if a member has the given permission
// for example, If you would like to check if user has the administrator
// permission you would use
// --- MemberHasPermission(s, guildID, userID, discordgo.PermissionAdministrator)
// If you want to check for multiple permissions you would use the bitwise OR
// operator to pack more bits in. (e.g): PermissionAdministrator|PermissionAddReactions
// =================================================================================
//     s          :  discordgo session
//     guildID    :  guildID of the member you wish to check the roles of
//     userID     :  userID of the member you wish to retrieve
//     permission :  the permission you wish to check for
func MemberHasPermission(s *discordgo.Session, guildID string, userID string, permission int) (bool, error) {
	member, err := s.State.Member(guildID, userID)
	if err != nil {
		if member, err = s.GuildMember(guildID, userID); err != nil {
			return false, err
		}
	}

	// Iterate through the role IDs stored in member.Roles
	// to check permissions
	for _, roleID := range member.Roles {
		role, err := s.State.Role(guildID, roleID)
		if err != nil {
			return false, err
		}
		if role.Permissions&permission != 0 {
			return true, nil
		}
	}

	return false, nil
}

func SaveModel(memberID string, chain *gomarkov.Chain) {
	data, err := json.Marshal(*chain)
	check(err)
	ok, err := Redis.Set(memberID, data, 0).Result()
	if ok != "OK" {
		check(errors.New("Result from redis command was not OK!"))
	}
}

func SaveModelToRedis(modelMap *ModelMap) {
	modelMap.Iterate(SaveModel)
}

func CanFindModel() bool {
	var size int64
	size, err := Redis.DBSize().Result()
	if err != nil {
		size = -1
	}
	return size > 0
}
