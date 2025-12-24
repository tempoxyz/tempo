import LucideSparkles from '~icons/lucide/sparkles'

export default function Footer() {
  return (
    <div className="flex">
      <div className="text-gray10 text-sm flex items-center gap-1.5">
        <span className="font-medium flex items-center gap-1">
          <LucideSparkles className="size-3 stroke-[2.5]" /> LLM?
        </span>
        <a
          href="/llms.txt"
          className="text-gray10"
          title="Machine-readable documentation for AI agents"
        >
          Read llms.txt
        </a>
      </div>
    </div>
  )
}
