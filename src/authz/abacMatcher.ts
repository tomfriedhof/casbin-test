import * as _ from "lodash";
import {InvalidInput} from "../common/errors/errors";

class Matcher  {
    constructor(private readonly op: any, private readonly params: any[], private readonly input: any) {}

    eval(): boolean {
        const p1 = _.nth(this.params, 0);
        const p2 = _.nth(this.params, 1);
        const p3 = _.nth(this.params, 2);
        const p4 = _.nth(this.params, 3);
        switch (this.op) {
            case "=":
                return this.eq(p1, p2);
            case "oneInEachAccessTag":
                return this.oneInEachAccessTag(p1, p2);
            case "hasSameLocationAs":
                return this.hasSameLocationAs(p1, p2);
            default:
                throw new InvalidInput(`unsupported operator: ${this.op}`);
        }
    }

    eq(lhs: any, rhs: any): boolean {
        lhs = _.get(this.input, lhs);
        rhs = _.get(this.input, rhs);
        if (_.isNil(lhs)) throw new InvalidInput(`op: ${this.op}, missing lhs: ${lhs}`);
        if (_.isNil(rhs)) throw new InvalidInput(`op: ${this.op}, missing rhs: ${rhs}`);
        return lhs === rhs;
    }

    oneInEachAccessTag(lhs: any, rhs: any): boolean {
        lhs = _.get(this.input, lhs);
        rhs = _.get(this.input, rhs);
        let found = true;
        const tagTypes = Object.keys(rhs);
        tagTypes.forEach(type => {
            for (const tag of rhs[type]) {
                if (!lhs[type].find((t: any) => t.id === tag.id)) {
                    found = false;
                    break;
                }
            }
            if (!found) return;
        });
        return found;
    }

    hasSameLocationAs(lhs: any, rhs: any): boolean {
        const position = _.get(this.input, lhs + '.attributes.position');
        lhs = _.get(this.input, lhs + '.attributes.accessTags.location');
        rhs = _.get(this.input, rhs + '.attributes.accessTags.location');

        let found = true;
        for (const tag of rhs) {
            if (!lhs.find((t: any) => t.id === tag.id)) {
                found = false;
                break;
            }
        }
        return found;
    }

}

export class AbacMatcher {
    constructor(private matchedPolicies: (any[])[] = [], private checkedPolicies: (any[])[] = []) {}

    /**
     * implements proxy pattern to capture policy matching result
     */
    match(policy: any[], input: any): boolean {
        this.checkedPolicies.push(policy);
        const obj = _.nth(policy, 0);
        const op = _.nth(policy, 1);
        const params = policy.slice(2);
        try {
            let matchResult = new Matcher(op, params, input).eval();
            if (matchResult) this.matchedPolicies.push(policy);
            return matchResult;
        } catch (err) {
            return false;
        }
    }

    getCheckedPolicies() {
        return this.checkedPolicies;
    }

    getMatchedPolicies() {
        return this.matchedPolicies;
    }

    /**
     * casbin matcher interface
     */
    static AbacMatcherWrapper(...args: any[]): boolean {
        // args = [r.matcher, p.act, p.obj, r.data, p.op, p.p1, p.p2]
        // extract abacMatcher from args
        // const abacMatcher = _.nth(args, 0);
        // args = args.splice(1);

        const p_obj = _.nth(args, 0);
        const r_input = _.nth(args, 1);
        const p_op = _.nth(args, 2);
        const p_pn = args.splice(3);
        const policy = _.reject([p_obj, p_op, ...p_pn], _.isNil);
        try {
            return new AbacMatcher().match(policy, r_input);
        } catch (err) {
            if (err instanceof InvalidInput) return false;
            throw err;
        }
    }
}
