==UEDllRemapper

This tool allow you to remap imports of module build with UE4 Modular LinkType to monolith executable,
allowing it to function in a monolith build and reference game functions successfully.
Function names and their addresses in executable are retrieved via .pdb file packaged with it.
It will also add required exports to game executable, so to load it successfully
you just need to call LoadLibrary in a process.

Usage:
```UEDllRemapper.exe ${GAME_EXECUTABLE_PATH} ${MODULE_DIRECTORY_PATH} ${PRIMARY_GAME_MODULE_NAME}```

Example:
```UEDllRemapper.exe ${GAME_PATH}\FactoryGame-Win64-Shipping.exe ${GAME_PATH}\Mods FactoryGame```
* `UEDllRemapper.exe ${GAME_PATH}\FactoryGame-Win64-Shipping.exe` specifies game executable for symbol resolving and exports patching
* `${GAME_PATH}\Mods` will be scanned for game modules, which will be remapped to use game executable
* `FactoryGame` specifies name of the primary game module

**Warning! This DOES NOT provide any method of hooking into the game, it just remaps module imports**
