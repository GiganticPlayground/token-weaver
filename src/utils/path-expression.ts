import { HttpError } from './http-error';

const bracketPattern = /\[(\d+|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\]/g;

function normalizeSegment(segment: string): string | number {
  if (/^\d+$/.test(segment)) {
    return Number(segment);
  }

  if (
    (segment.startsWith('"') && segment.endsWith('"')) ||
    (segment.startsWith("'") && segment.endsWith("'"))
  ) {
    return segment.slice(1, -1);
  }

  return segment;
}

function tokenizePath(expression: string): Array<string | number> {
  if (expression === '$') {
    return [];
  }

  if (!expression.startsWith('$')) {
    throw new HttpError(500, `Invalid path expression: ${expression}`);
  }

  const segments: Array<string | number> = [];
  const dottedSegments = expression
    .slice(1)
    .split('.')
    .filter((segment) => segment.length > 0);

  for (const dottedSegment of dottedSegments) {
    const propertyName = dottedSegment.split('[')[0];
    if (propertyName) {
      segments.push(propertyName);
    }

    const matches = dottedSegment.matchAll(bracketPattern);
    for (const match of matches) {
      segments.push(normalizeSegment(match[1]!));
    }
  }

  return segments;
}

export function resolvePath(expression: string, input: unknown): unknown {
  return tokenizePath(expression).reduce<unknown>((current, segment) => {
    if (current === null || current === undefined) {
      return undefined;
    }

    if (typeof segment === 'number') {
      return Array.isArray(current) ? current[segment] : undefined;
    }

    if (typeof current === 'object') {
      return (current as Record<string, unknown>)[segment];
    }

    return undefined;
  }, input);
}

function parseLiteral(value: string): unknown {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }

  if (value === 'true') {
    return true;
  }

  if (value === 'false') {
    return false;
  }

  if (value === 'null') {
    return null;
  }

  const asNumber = Number(value);
  if (!Number.isNaN(asNumber) && value.trim() !== '') {
    return asNumber;
  }

  return value;
}

export function evaluateCondition(expression: string, input: unknown): boolean {
  const trimmed = expression.trim();
  for (const operator of ['==', '!=']) {
    const index = trimmed.indexOf(operator);
    if (index > -1) {
      const left = trimmed.slice(0, index).trim();
      const right = trimmed.slice(index + operator.length).trim();
      const leftValue = left.startsWith('$') ? resolvePath(left, input) : parseLiteral(left);
      const rightValue = right.startsWith('$') ? resolvePath(right, input) : parseLiteral(right);
      return operator === '==' ? leftValue === rightValue : leftValue !== rightValue;
    }
  }

  const value = trimmed.startsWith('$') ? resolvePath(trimmed, input) : parseLiteral(trimmed);
  return Boolean(value);
}
