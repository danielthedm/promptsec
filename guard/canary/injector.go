package canary

// separator is placed between the original input and the canary token so the
// token does not merge with user text.
const separator = "\n\n[system:canary] "

// injectToken appends the canary token to the input, separated by a clear
// delimiter. The separator is designed to look like a system-level annotation
// so the model treats it as metadata rather than user content.
func injectToken(input, token string) string {
	return input + separator + token
}
