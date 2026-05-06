package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"forensiq/internal/fcase"
	"forensiq/internal/llm"
	"forensiq/internal/schema"
)

var askCmd = &cobra.Command{
	Use:   "ask <file.fcase> <question>",
	Short: "Ask the LLM a question about the case (requires Ollama)",
	Long: `Uses a local LLM via Ollama to answer forensic questions about the case.

  forensiq ask case.fcase "What processes had suspicious network activity?"
  forensiq ask case.fcase "Summarize the attack timeline"
  forensiq ask case.fcase "What persistence mechanisms were found?"
  forensiq ask case.fcase --model llama3.2 "Were there any lateral movement indicators?"

Requires Ollama running locally: https://ollama.com
Default model: qwen2.5:7b  (run: ollama pull qwen2.5:7b)`,
	Args: cobra.MinimumNArgs(2),
	RunE: runAsk,
}

var (
	flagAskModel string
	flagAskBase  string
)

func init() {
	askCmd.Flags().StringVar(&flagAskModel, "model", "", "Ollama model (default: qwen2.5:7b)")
	askCmd.Flags().StringVar(&flagAskBase, "ollama", "http://localhost:11434", "Ollama base URL")
}

func runAsk(cmd *cobra.Command, args []string) error {
	casePath := args[0]
	question := strings.Join(args[1:], " ")

	c, err := fcase.Open(casePath, "")
	if err != nil {
		return err
	}
	defer c.Close()

	if err := schema.Apply(c); err != nil {
		return err
	}

	client := llm.New(flagAskBase, flagAskModel)

	// List available models on first use to give helpful guidance
	models, err := client.Models()
	if err != nil {
		return fmt.Errorf("cannot reach Ollama at %s — is it running?\n  Start with: ollama serve\n  Error: %w", flagAskBase, err)
	}
	if len(models) == 0 {
		return fmt.Errorf("no models installed in Ollama\n  Install one: ollama pull qwen2.5:7b")
	}

	// Auto-select model if not specified
	if flagAskModel == "" {
		preferred := []string{"qwen2.5:7b", "qwen2.5", "llama3.2", "llama3", "mistral", "phi3"}
		selected := models[0]
		for _, pref := range preferred {
			for _, m := range models {
				if strings.HasPrefix(m, pref) {
					selected = m
					goto found
				}
			}
		}
	found:
		client.Model = selected
		fmt.Printf("[LLM] Using model: %s\n", selected)
	}

	fmt.Printf("[LLM] Building forensic context from %s...\n", casePath)
	ctx := llm.BuildContext(c.DB())

	fmt.Printf("[LLM] Querying %s...\n\n", client.Model)
	answer, err := client.Ask(llm.SystemPrompt(), ctx+"\n\nQuestion: "+question)
	if err != nil {
		return fmt.Errorf("LLM error: %w", err)
	}

	fmt.Println(answer)
	return nil
}
