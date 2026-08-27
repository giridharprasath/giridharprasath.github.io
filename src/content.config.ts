import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const posts = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/posts' }),
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),
    tags: z.array(z.string()).optional(),
    summary: z.string().optional(),
    mathJax: z.boolean().optional(),
    layout: z.string().optional()
  })
});

export const collections = { posts };
