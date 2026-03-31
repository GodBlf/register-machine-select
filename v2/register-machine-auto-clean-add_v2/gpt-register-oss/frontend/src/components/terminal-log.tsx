import { useEffect, useRef } from "preact/hooks";
import type { LogLine } from "../types/runtime";

type TerminalLogProps = {
  lines: LogLine[];
};

export function TerminalLog(props: TerminalLogProps) {
  const { lines } = props;
  const terminalRef = useRef<HTMLDivElement>(null);
  const shouldStickToBottomRef = useRef(true);

  const handleScroll = () => {
    const node = terminalRef.current;
    if (!node) {
      return;
    }
    const distanceToBottom = node.scrollHeight - node.scrollTop - node.clientHeight;
    shouldStickToBottomRef.current = distanceToBottom < 32;
  };

  useEffect(() => {
    if (terminalRef.current && shouldStickToBottomRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div class="terminal" ref={terminalRef} onScroll={handleScroll}>
      {lines.map((line) => (
        <div class="log-row" key={line.id}>
          <span class="log-dim">{line.prefix}</span>{" "}
          <span class={`log-${line.tone}`}>{line.timestamp}</span>{" "}
          <span>{line.message}</span>
        </div>
      ))}
    </div>
  );
}
