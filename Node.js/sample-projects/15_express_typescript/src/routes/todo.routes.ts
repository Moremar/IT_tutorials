import { Router, Request, Response } from 'express';
import { Todo } from '../models/todos.model';

const router = Router();

const todos: Todo[] = [
    { id: 1, text: 'Learn Node', completed: true },
    { id: 2, text: 'Learn Docker', completed: true },
    { id: 3, text: 'Rule the World', completed: false }
];

router.get('/', (req: Request, res: Response) => {
    res.json(todos);
});

router.post('/', (req: Request, res: Response) => {
    const { text } = req.body;
    const todo = {
        id: todos.length + 1,
        text,
        completed: false
    };
    todos.push(todo);
    res.status(201).json(todo);
});

router.put('/:id', (req: Request, res: Response) => {
    const id = parseInt(req.params.id);
    const { text, completed } = req.body;
    const todoIndex = todos.findIndex(x => x.id === id);
    if (todoIndex == -1) {
        return res.status(404).json({ error: 'Todo not found' });
    }
    todos[todoIndex] = {
        ...todos[todoIndex],
        text: text || todos[todoIndex].text,
        completed: completed || todos[todoIndex].completed
    };
    res.json(todos[todoIndex]);
});

router.delete('/:id', (req: Request, res: Response) => {
    const id = parseInt(req.params.id);
    const todoIndex = todos.findIndex(x => x.id === id);
    if (todoIndex == -1) {
        return res.status(404).json({ error: 'Todo not found' });
    }
    const todo = todos.splice(todoIndex, 1);
    res.json(todo[0]);
});

export default router;