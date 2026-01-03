import * as React from "react";

/**
 * if you just want to run some JS logic and generate output in markdown, use this
 */

export function Fn(props: { fn: () => Promise<React.ReactNode> }) {
  const [result, setResult] = React.useState<React.ReactNode>();
  React.useEffect(() => {
    props.fn().then(setResult);
  }, [props.fn]);
	return <React.Fragment>{result}</React.Fragment>;
}
