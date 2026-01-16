import { tips } from 'virtual:tips-data'

const GITHUB_BASE_URL =
  'https://github.com/tempoxyz/tempo/blob/main/docs/pages/protocol/tips'

export function TipsList() {
  if (!tips || tips.length === 0) {
    return <p>No TIPs found.</p>
  }

  return (
    <ul>
      {tips.map((tip) => (
        <li key={tip.id}>
          <a
            className="vocs_Anchor"
            href={`${GITHUB_BASE_URL}/${tip.fileName}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            {tip.id}: {tip.title}
          </a>
        </li>
      ))}
    </ul>
  )
}

export default TipsList
