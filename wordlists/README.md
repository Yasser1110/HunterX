Place your wordlists here.

Starter files created by `hunterx init`:
  common.txt      small generic paths
  parameters.txt  common query parameter names
  extensions.txt  file extensions for fuzzing

Recommended medium/large lists (drop-in, then reference them from config/wordlists.yaml):
  raft-medium.txt / raft-large.txt  (danielmiessler/SecLists)
  api.txt, graphql.txt, backup.txt, sensitive.txt

HunterX selects lists adaptively based on detected technology (Phase 5 build),
so the large list is only used when the application behavior justifies it.