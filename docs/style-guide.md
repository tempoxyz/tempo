# Documentation Style Guide

This guide exists as the **one true reference** for making documentation decisions and settling debates quickly. Great documentation is well-organized, consistent, translatable, trustworthy, and appropriately technical for developers.

## Quick Reference

Use this section for fast lookups:

| Question | Answer |
|----------|--------|
| Active or passive voice? | **Active**: "The API returns a token" not "A token is returned" |
| Present or future tense? | **Present**: "returns" not "will return" |
| Oxford comma? | **Yes**: "tokens, payments, and charges" |
| Numbers under 10? | **Spell out**: "three tokens" (except with units: "5 MB") |
| Currency format? | **ISO code + amount**: "100 USD" not "$100" |
| Contractions? | **Yes**: "don't," "can't," "you're" (avoid awkward ones like "it'll") |
| Latin abbreviations? | **No**: Use "for example" not "e.g.", "that is" not "i.e." |
| Heading style? | **Sentence case**: "Send a payment" not "Send a Payment" |
| Code font for API objects? | **Yes**: Use `PaymentIntent` with link to reference |
| Bold for UI elements? | **Yes**: Click **Settings** > **API Keys** |

---

## Core Philosophy

### Consistency Is Paramount

Inconsistency frustrates users and can be misinterpreted as different meanings. If you call something a "token" in one place and a "credential" in another, users will assume they're different things.

**Rule**: Use the exact same term every time you refer to the same concept. Don't vary word choice for elegance—this is technical writing, not prose.

### Users Scan, They Don't Read

Structure all content for scanning, not word-by-word reading. Users skim headings, code examples, and bullet points. They read body text only when they must.

**Implications**:
- Front-load important information
- Use short paragraphs (2-4 sentences max)
- Break up text with headings, lists, and code
- Make headings descriptive and actionable

### Be Ruthlessly Concise

Any text that doesn't increase clarity should be cut. Every word must earn its place.

**Before**: "In order to be able to successfully create a new payment, you will need to make sure that you have first obtained the necessary API credentials from your dashboard."

**After**: "To create a payment, obtain API credentials from your dashboard."

---

## Voice & Tone

### Write Like a Developer Talking to a Developer

Be conversational, technical, and matter-of-fact. Avoid marketing language, cuteness, and unnecessary enthusiasm.

**Good**: "Call the API endpoint to retrieve the transaction."
**Bad**: "Simply leverage our powerful API to easily fetch your transaction!"

### Be Appropriately Technical

Our primary audience is developers. Use proper technical terms. Make expectations clear. Don't "dumb down" content.

**Good**: "The webhook sends a POST request with a JSON payload."
**Bad**: "The system will send some information to your server."

### Stay Positive and Definitive

Don't hedge or use tentative language. Be confident about what's true.

**Avoid**: may, might, probably, perhaps, could possibly
**Use**: must (for requirements), can (for capabilities), is/are (for facts)

---

## Grammar & Style

### Use Present Tense

Present tense is easier to read and often means shorter, more common words.

**Good**: "The API returns a token."
**Bad**: "The API will return a token."

**Exception**: Use future tense only when timing is essential to the meaning.

### Use Active Voice

Active voice is simpler, clearer, and translates better.

**Good**: "The server validates the signature."
**Bad**: "The signature is validated by the server."

**Exception**: Passive voice is acceptable when active voice creates convoluted sentences or when the actor is unknown/irrelevant.

### Use Strong Verbs

Avoid weak verbs like "be," "have," "make," "do." Avoid "will" and "should" in most cases.

**Weak**: "You should make a call to the API."
**Strong**: "Call the API."

**"Will" and "Should"**: Almost never necessary in technical docs. Use "must" for requirements, "can" for capabilities, present tense for facts. Use "should" only for optional recommendations.

### Use Indicative Mood (Default to Facts)

Express certainty about what's true. Use imperative mood for instructions.

**Indicative** (facts): "The endpoint requires authentication."
**Imperative** (instructions): "Authenticate before calling the endpoint."

### Pronouns

- **You**: Use second-person "you" for the reader
- **We**: Minimize; use only colloquially to refer to your company
- **First person**: Don't write in first person ("I," "my")
- **Let's**: Don't use (implies "we" as reader + writer, which doesn't exist)

### Contractions

Use contractions for a conversational tone. They're natural and easier to read.

**Use**: don't, can't, you're, it's, we're, won't
**Avoid**: it'll, this'll, that'll (awkward)

### Oxford Comma

Always use the serial comma in lists of three or more items.

**Good**: "tokens, payments, and charges"
**Bad**: "tokens, payments and charges"

### Dashes and Hyphens

**Em dash** (—): Use for breaks in thought. No spaces on either side.
_Markdown_: `---` or `&mdash;`
_Example_: "The API—unlike the SDK—requires manual error handling."

**En dash** (–): Use for ranges or negative amounts.
_Markdown_: `--` or `&ndash;`
_Example_: "Pages 10–15" or "–$50"

**Hyphen** (-): Use for compound modifiers that precede a noun.
_Example_: "client-side validation" (adjective) but "client side" (noun)

**General rule**: Minimize dashes—too many is distracting.

### Numbers

**Spell out** numbers less than 10: "three tokens," "five minutes"
**Use numerals** for 10 and above: "15 tokens," "100 requests"
**Always use numerals** with units: "5 MB," "2 seconds," "API version 3"
**Never start** a sentence with a numeral—rewrite or spell it out
**Ranges**: Use en dash without "from" or "between": "10–20 requests"

### Currencies

Always use three-letter ISO codes with amounts. Don't use currency symbols.

**Good**: "100 USD," "50 EUR"
**Bad**: "$100," "€50"

**Why**: Currency symbols aren't unique and can be misinterpreted across regions.

**Currency names**: Always lowercase: "dollar," "euro," "bitcoin"
**Currency codes**: Always uppercase: "USD," "EUR," "BTC"

### Dates and Times

Use month names or ISO 8601 format. Never use ambiguous formats.

**Good**: "January 26, 2025" or "2025-01-26"
**Bad**: "1/26/25" or "26/1/25" (ambiguous across regions)

**Times**:
- 12-hour: "11:30 PM" (space before AM/PM)
- 24-hour: Include time zone

### No Latin Abbreviations

Don't use i.e., e.g., etc., et al.

**Use instead**: "that is," "for example," "and so on"

**Why**: Clearer for international audiences and easier to translate.

---

## Lists

### Introducing Lists

Introduce with a complete sentence (period) or fragment (colon). Never use ellipsis (…).

**Good**: "The API supports three authentication methods:"
**Bad**: "The API supports three authentication methods..."

### Numbered Lists

Use **only for sequential operations**. Each item should be a complete sentence with terminating punctuation.

```markdown
1. Obtain your API key from the dashboard.
2. Include the key in the Authorization header.
3. Make a POST request to the endpoint.
```

**Optional steps**: Precede with "(Optional)" in parentheses.

**Sequential UI navigation**: Use right angle brackets with spaces:
Click **Account** > **Settings** > **API Keys**

### Bulleted Lists

Use for **non-sequential items**. Require at least two items.

**Fragment items** (no terminating punctuation):
- Fast transactions
- Low fees
- Global reach

**Complete sentence items** (with terminating punctuation):
- The API validates all signatures before processing.
- Webhooks retry failed deliveries up to three times.
- Rate limits apply to all endpoints.

**Parallel structure**: Start each item the same way (all fragments, all sentences, all starting with verbs, etc.).

---

## Documentation Structure

### Document Types

**Integration guide**: End-to-end walkthrough of implementing a feature
**Feature guide**: Deep dive into a specific capability
**How it works**: Explanation of underlying concepts or architecture
**Migration guide**: Step-by-step process for upgrading or changing implementations

**Never use FAQs** for public-facing docs—they create poor UX and suggest disorganized thinking.

### Titles

Use sentence case. Best titles include an action in imperative mood.

**Good**: "Send a payment," "Authenticate with API keys"
**Acceptable**: "Webhooks," "Account management"
**Bad**: "How to Send a Payment," "Sending Payments"

### Descriptions (Frontmatter)

Include for every doc. Provides details about purpose and what the user can accomplish.

- More detailed than subtitle
- Include keywords for search results
- One to two sentences max

### Introductions

Short overview (2-3 sentences or one short paragraph) of the doc's purpose. Don't overexplain. Users skim.

### Headings

**Sentence case**: "Create a webhook endpoint" not "Create a Webhook Endpoint"

**Guidelines**:
- Keep short (max 10-12 words)
- Use imperative mood: "Configure authentication," "Handle errors"
- Use parallel structure across same-level headings
- Never skip levels (h2 > h3 > h4, not h2 > h4)
- Never nest more than 3 levels deep
- Never use ampersands (&) or terminating punctuation
- Always assign named anchors/IDs—don't rely on auto-generated ones

**Strive for balance**: Have at least 2 subheadings of the same level, or reconsider the structure.

**Avoid stacked headings**: Don't place two headings in a row without body text between them.

### Callouts

Use sparingly to highlight critical information. Maximum 3 per page.

**Good uses**:
- Security warnings
- Breaking changes
- Common gotchas

**Avoid**:
- At the top of sections (can overload readers)
- Warnings without context
- Multiple paragraphs (keep to 1-2 sentences)

### Next Steps / See Also

Place at the bottom of the page, before the footer. Include 2-5 logical next steps. No text between heading and links.

Fine to omit if there are no clear next steps.

---

## Code Examples

### Guiding Principles

Code examples should:
- Be **valid, working code** in the given language
- Be **concise**—show only what's necessary
- Be **secure**—implement real-world security practices
- **Build up complexity** gradually (basics first)
- Use **meaningful names** for variables, functions, classes
- **Separate code from response**—make clear what you're executing vs. what you expect

### What to Avoid

- Obvious comments
- Exception handling (unless intrinsic to the point)
- Library imports (unless intrinsic to the point)
- Long lines of code
- Exclusionary language in example names/data

### Before the Code Block

Make clear:
- Purpose of the code
- Scenario where it would be used
- Any assumptions being made
- Requirements (authentication, dependencies, etc.)

### Placeholders

**Preference**: Use actual values whenever possible (including actual API keys for clarity).

**If placeholders needed**: Use syntax `{{VARIABLE_NAME}}` with underscores.
Example: `{{API_KEY}}`, `{{USER_ID}}`

### Comments

- Place comments on the line **before** the commented code
- Write in complete sentences
- Avoid obvious comments like `// Call the API`

### Security

Make code examples secure. When taking shortcuts, acknowledge it explicitly.

**Good**:
```javascript
// WARNING: Never expose API keys in client-side code
// This example is for demonstration only
const apiKey = "{{API_KEY}}";
```

Never convey absolute security. Use qualifiers:
- "more secure," "less secure"
- "helps protect," "reduces risk"
- "not secure" (not "insecure" or "unsecure")

---

## Common Pitfalls to Avoid

### Don't Ask Questions

Readers come for answers, not questions. Avoid rhetorical questions.

**Bad**: "Want to accept payments? Need to authenticate users?"
**Good**: "Accept payments by integrating the payments API."

### Don't Try to Be Funny

Avoid humor, cuteness, clever wordplay, sarcasm, and slang.

**Bad**: "Now for the fun part!" or "Easy peasy!"
**Good**: "Configure the webhook endpoint."

**Why**: Humor rarely translates well, especially for international audiences. Be conversational, but stay professional.

### Don't Use Low-Value Words

These words add no information and can undermine trust:

**Avoid**: just, simply, easily, obviously, clearly, only (unless literal)

**Bad**: "Simply add the API key to easily authenticate."
**Good**: "Add the API key to authenticate."

**Why**: If the reader finds it difficult, they'll lose trust in your documentation.

### Don't Overuse Parentheticals

Parentheses (and em dashes) weaken text and decrease comprehension. If something needs to be said, say it directly. If it's useful but not vital, link to another resource.

**Bad**: "The API (which supports REST) returns JSON (or XML, if specified)."
**Good**: "The API returns JSON. Specify XML in the Accept header if needed."

### Don't Use Exclusionary Language

- No gendered pronouns (use "they" or rewrite)
- Use diverse names in examples (not gender/ethnicity-specific)
- Person-first language for disabilities: "people with vision impairment" not "blind people"

### Don't Anthropomorphize

Don't suggest systems are sentient or willful. Harder for non-native speakers and translation.

**Avoid**: wants, thinks, knows, likes, assumes, decides
**Acceptable**: allows, recognizes, permits, sees

**Bad**: "The API knows which token to use."
**Good**: "The API determines which token to use based on the authentication header."

### Don't Suggest How Users Should Feel

Never tell users a task is easy, fast, or straightforward. If they disagree, you've lost their trust.

**Bad**: "It's easy to set up webhooks."
**Good**: "Set up webhooks in three steps."

Write with empathy, but don't assume users' feelings or abilities.

---

## Links & Navigation

### URL Structure

- Use hyphens, never underscores (exception: auto-generated IDs)
- All lowercase
- Avoid numbers (spell them out: `/guide/three-steps` not `/guide/3-steps`)

### When to Link

- Leverage existing content by linking to related resources
- Use links for **nonessential information only**
- Users shouldn't need to visit another page for required information
- Link to specific sections using anchors when appropriate

### Link Text

Keep brief (typically 4 words or fewer). Match the title or heading you're linking to, including capitalization.

**Good**: "Learn more about [webhooks](/guide/webhooks)."
**Bad**: "Click [here](/guide/webhooks) to learn about webhooks."

**Never**:
- Link from headings (only from body text)
- Link from "here," "this page," or "click here"
- Include punctuation in link text (place it outside)

### Capitalization in Links

- **Sentence case**: For general references to concepts
- **Title case**: When pointing to a doc by its exact title

**Example**: "Use [webhooks](/guide/webhooks) to receive real-time events." (concept)
**Example**: "See the [Webhooks Guide](/guide/webhooks) for implementation details." (document title)

---

## Formatting

### Bold

Use for:
- UI labels: Click **Settings**
- Filenames: Open **config.json**
- Unlinked URLs: Visit **api.example.com**

Don't use for:
- Introducing terminology (use italics once, then normal text)
- Emphasis (use italics sparingly)

### Code Font

Use for:
- Object names: `PaymentIntent`
- Methods/functions: `createToken()`
- Properties: `amount`, `currency`
- Commands: `npm install`
- Status codes: `200 OK`
- Values provided by user: `{{API_KEY}}`

Link the first instance of API objects/methods/properties to the API reference.

Don't apply code font to linked text—links provide enough visual distinction.

### Italics

Use sparingly for:
- Introducing new terminology (first use only)
- Emphasis (rarely)

Never use underlines (confused with links).

### Mixed Formatting

**Never** mix font decoration styles:
- Not code font + bold
- Not code font + italics
- Not font decoration + link

### Quotation Marks

Use for:
- Words/phrases that might confuse readers
- Suggested text for users to send (emails, messages)
- First use of fictitious business names

Don't use for:
- UI elements (use bold)
- Emphasis or air quotes

Ending punctuation always goes inside quotation marks.

---

## Capitalization

### Products and Features

**Products**: Title case when referring to the product name
**Features**: Sentence case (common noun) unless it's a branded feature

**Why**: Capitalization isn't a reflection of importance. It's distracting when words are capitalized without clear reason.

### Object Names

Capitalize and use code font when referring to API objects: `Invoice`, `Token`, `PaymentIntent`

Use common noun (no code font) when referring to the actual individual instance: "an invoice," "the user's token"

### Headings

Always sentence case: "Configure your webhook endpoint"

### Currency

**Names**: lowercase: "dollar," "euro," "bitcoin"
**Codes**: uppercase: "USD," "EUR," "BTC"

### Boolean

Capitalize "Boolean" when referring to the data type.

Boolean values `true` and `false`: lowercase, no formatting, no quotes.

**Why**: Different languages capitalize differently. Using `true` means "whatever your version of 'true' is."

### Avoid "The" in Headings

Don't begin headings or titles with "the."

**Good**: "Payment methods"
**Bad**: "The payment methods"

---

## Common Terminology

Use consistent terminology. This list settles common debates:

| Term | Usage | Notes |
|------|-------|-------|
| API | Singular: "The API consists of multiple endpoints" | Always singular |
| autofill | One word | |
| back end, front end | Two words (noun); back-end, front-end (adjective) | "The back end runs Node.js" / "back-end server" |
| backup | One word (noun/adj); "back up" (verb) | "Create a backup" / "back up your data" |
| Boolean | Capitalized | Data type |
| client-side, server-side | Hyphenated (adjective); "client side" (noun) | "client-side code" / "runs on the client side" |
| command line | Two words (noun); command-line (adjective) | "Use the command line" / "command-line tool" |
| curl | Lowercase | Not "cURL" |
| e-commerce | Hyphenated | Not "ecommerce" or "eCommerce" |
| ID | Always "ID," never "id" or "Id" | Plural: "IDs" |
| key-value pair | Not "key/value" | |
| login | One word (noun/adj); "log in" (verb) | "Enter your login" / "log in to your account" |
| mobile | Never "cell phone" | |
| null | Lowercase, no formatting | |
| payout | One word (noun/adj); "pay out" (verb) | "Request a payout" / "pay out funds" |
| postal code | Not "ZIP code" | International audience |
| setup | One word (noun/adj); "set up" (verb) | "Complete the setup" / "set up your account" |
| signup | One word (noun/adj); "sign up" (verb) | "The signup flow" / "sign up for an account" |
| time zone | Two words | Not "timezone" |
| URL | "a URL" (not "an URL") | Omit https:// and www. unless unusual |
| web server | Two words | |
| website | One word | |

---

## UI Elements

### General Guidelines

Match exact wording, case, and punctuation of the UI (omit trailing punctuation).

Use bold for titles, labels, and options.

Use `>` for UI paths (not bold, space on each side):
Click **Settings** > **API Keys** > **Create Key**

### Specific Elements

| Element | Usage |
|---------|-------|
| Button | "Click the **Submit** button" or "Click **Submit**" |
| Checkbox | One word; can be "selected," "cleared," "disabled," "enabled" (never "checked" or "unchecked") |
| Dialog | Not "dialog box" or "pop-up window" |
| Menu (…) | "The overflow menu" |

Don't include element type unless required for clarity:
**Good**: "Click **Submit**"
**Acceptable**: "Click the **Submit** button" (if multiple UI elements named "Submit")

### Navigation

Avoid directional language ("above," "below," "on the right") unless the UI component is hard to find.

**Good**: "In the **API Keys** section, click **Create**."
**Acceptable**: "In the sidebar on the left, click **Settings**." (only if hard to find)

---

## Final Notes

This guide prioritizes:

1. **Speed**: Quick decisions, clear rules to avoid debates
2. **Consistency**: Use the same terms, structure, and style across all docs
3. **Developer focus**: Appropriately technical, code-centric, precise
4. **Clarity**: Active voice, present tense, strong verbs, concise writing
5. **International accessibility**: Translation-friendly, clear for non-native speakers

When in doubt, ask: "Does this help the user accomplish their goal?" If not, cut it.

Keep this guide as the single source of truth. Update it as you learn what works for your team.
