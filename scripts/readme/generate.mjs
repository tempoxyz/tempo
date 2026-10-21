import { readFileSync, writeFileSync } from "node:fs";
import Handlebars from "handlebars";

const root = new URL("../../", import.meta.url);
const data = Object.fromEntries(
  ["mainnet", "testnet"].map((network) => [
    network,
    JSON.parse(readFileSync(new URL(`${network}-network-identity.json`, root), "utf8")),
  ]),
);
const template = readFileSync(new URL("README.md.hbs", root), "utf8");
const rendered = Handlebars.compile(template, { strict: true, noEscape: true })(data);
const readme = new URL("README.md", root);

writeFileSync(readme, rendered, "utf8");
