import type { Rule, RuleInput } from '../model/types';

// Floating rules apply to several interfaces, all of them, or groups;
// they're listed on their own tab and generated before interface rules.
export const isFloating = (r: Rule | RuleInput) => r.interfaces.length !== 1 || (r.groups?.length ?? 0) > 0;
