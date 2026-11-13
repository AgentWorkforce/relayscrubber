// Runtime-only loader for pinned pipeline TypeScript sources; emits no build.
import {registerHooks, createRequire} from 'node:module';
import {existsSync, readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
const typescript = createRequire(import.meta.url)(process.env.QUALIFICATION_TYPESCRIPT_MODULE ?? 'typescript');

registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('.') && specifier.endsWith('.js') && context.parentURL?.startsWith('file:')) {
      const target = new URL(specifier.slice(0, -3) + '.ts', context.parentURL);
      if (!existsSync(new URL(specifier, context.parentURL)) && existsSync(target))
        return next(target.href, context);
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url.startsWith('file:') && url.endsWith('.ts'))
      return {format: 'module', shortCircuit: true,
        source: typescript.transpileModule(readFileSync(fileURLToPath(url), 'utf8'), {
          fileName: fileURLToPath(url), compilerOptions: {target: typescript.ScriptTarget.ES2022, module: typescript.ModuleKind.ESNext},
        }).outputText};
    return next(url, context);
  },
});
