# dump writable buffer on function return

You can use `get_hooks(functions)` with functions being a list of function names to generate a dictionary listing all writable variables inside the respective function.
This dictionary can be used with `install_dbg_hook_dump(hooks)` to register a debugger hook which will dump the hooked buffer when the function returns.

Use `remove_dbg_hook_dump()` to unhook the debugger.


```python
functions = [ 'obfsfunc_290', 'obfsfunc_291', 'obfsfunc_292', 'obfsfunc_293', 'obfsfunc_294', 'rolling_xor', ... ]
hooks = get_hooks(functions)
install_dbg_hook_dump(hooks)
```
