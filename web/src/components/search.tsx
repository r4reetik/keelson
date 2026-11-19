// The search box of a list the server filters (Images, Dependencies): thousands of
// rows that can't be searched in the browser.
//
// What is typed stays in the box and is never held up by the list: a search is
// asked for once typing pauses, the page's request for the previous one is dropped
// when the next starts (useApi), and the box shows a spinner from the first key
// until the rows on screen are the ones for what it says. The address catching up
// with the box never rewrites it, which used to swallow keys typed meanwhile.

import { useCallback, useEffect, useRef, useState } from "react";
import { InputGroup, Loader, cn } from "@cloudflare/kumo";
import { MagnifyingGlassIcon, XIcon } from "@phosphor-icons/react";

/** How long typing must pause before a search is asked for. Enter asks at once. */
export const SEARCH_PAUSE_MS = 200;

/** What is searched for: spaces at either end don't make a new search, so a space typed between two words asks for nothing. */
export const searchTerm = (text: string) => text.trim();

export function SearchBox({
  placeholder,
  label = placeholder,
  value,
  onChange,
  busy = false,
  className,
}: {
  placeholder: string;
  /** What a screen reader calls the box; the placeholder when it says enough. */
  label?: string;
  /** The search the list shows now, from the address. */
  value: string;
  onChange: (term: string) => void;
  /** The list is loading rows, for this search or anything else. */
  busy?: boolean;
  className?: string;
}) {
  const [text, setText] = useState(value);
  // What this box last asked for. The address arriving at it is not news; anything else is (Clear filters, Back).
  const asked = useRef(value);
  const change = useRef(onChange);
  change.current = onChange;
  useEffect(() => {
    if (value === asked.current) return;
    asked.current = value;
    setText(value);
  }, [value]);

  const ask = useCallback((term: string) => {
    if (term === asked.current) return;
    asked.current = term;
    change.current(term);
  }, []);
  useEffect(() => {
    const term = searchTerm(text);
    if (term === asked.current) return;
    const timer = setTimeout(() => ask(term), SEARCH_PAUSE_MS);
    return () => clearTimeout(timer);
  }, [text, ask]);

  const clear = () => {
    setText("");
    ask("");
  };
  const searching = busy || searchTerm(text) !== value;
  return (
    <InputGroup className={cn("w-full min-w-48 sm:w-64", className)}>
      <InputGroup.Addon>
        <MagnifyingGlassIcon />
      </InputGroup.Addon>
      <InputGroup.Input
        aria-label={label}
        placeholder={placeholder}
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") ask(searchTerm(text));
          else if (e.key === "Escape" && text) clear();
        }}
      />
      {(searching || text) && (
        <InputGroup.Addon align="end" className="pr-1">
          {searching ? (
            // The size of the clear button it takes the place of, so the box doesn't shift when one replaces the other.
            <span role="status" aria-label="Searching" className="flex size-6.5 items-center justify-center">
              <Loader size="sm" />
            </span>
          ) : (
            <InputGroup.Button shape="square" icon={XIcon} aria-label="Clear search" onClick={clear} />
          )}
        </InputGroup.Addon>
      )}
    </InputGroup>
  );
}
