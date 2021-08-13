import * as Lab from '@hapi/lab';
import * as _ from "lodash";
import { expect } from '@hapi/code';

import { Enforcer, newEnforcer, newModel } from "casbin";
import {AbacMatcher} from "../../src/authz/abacMatcher";
import { MongooseAdapter } from "casbin-mongoose-adapter";

const lab = Lab.script();
const { suite, test } = lab;

export { lab };

suite('Uptape Policy Enforcement,', () => {
    test('should allow when access tags are the same', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        const user = { attributes: { accessTags: { location: [ { id: 'testing' }, { id: 'testing2' }  ], department: [ { id: 'bebe' }]}}};
        const uptape = { attributes: { accessTags: { location: [ { id: 'testing2' } ], department: [ { id: 'bebe' }]} }};

        await testEnforce(
            enforcer,
            {
                sub: 'tom',
                input: { user, uptape },
                obj: 'uptape'
            },
            true
        );
        await testEnforce(
            enforcer,
            {
                sub: 'kevin',
                input: { user, uptape },
                obj: 'uptape'
            },
            true
        );
        await testEnforce(
            enforcer,
            {
                sub: 'landre',
                input: { user, uptape },
                obj: 'uptape'
            },
            true
        );
        await testEnforce(
            enforcer,
            {
                sub: 'kandice',
                input: { user, uptape },
                obj: 'uptape'
            },
            false
        );
    });
    test('should deny when access tags are not the same', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        const subject = { accessTags: { location: [ { id: 'testing' }, { id: 'testing2' }  ], department: [ { id: 'bebe' }]}};
        const resource = { accessTags: { location: [ { id: 'testing3' } ], department: [ { id: 'bebe' }]} };

        await testEnforce(
            enforcer,
            {
                sub: 'kevin',
                input: { subject, resource },
                obj: 'uptape'
            },
            false
        );
    });
});

suite('Contact Policy Enforcement,', () => {
    const contact = { attributes: { assignedTo: 'billy' } };

    test('should allow when user is assigned to contact', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        const user = { id: 'billy', accessTags: { location: [ { id: 'testing' }  ], department: [ { id: 'bebe' }]} };

        await testEnforce(
            enforcer,
            {
                sub: 'landre',
                input: { user, contact },
                obj: 'contact'
            },
            true
        );
        await testEnforce(
            enforcer,
            {
                sub: 'kandice',
                input: { user, contact },
                obj: 'contact'
            },
            false
        );
    });

    test('should allow when manager has same location of user assigned to contact', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        const user = { id: 'bobby', attributes: { position: 'manager', accessTags: { location: [ { id: 'testing' }  ], department: [ { id: 'bebe' }]} }};
        const assignedUser = { id: 'billy', attributes: { accessTags: { location: [ { id: 'testing' }  ], department: [ { id: 'bebe' }]} }};

        await testEnforce(
            enforcer,
            {
                sub: 'kevin',
                input: { user, assignedUser },
                obj: 'contact'
            },
            true
        );
        await testEnforce(
            enforcer,
            {
                sub: 'tom',
                input: { user, assignedUser },
                obj: 'contact'
            },
            true
        );
        await testEnforce(
            enforcer,
            {
                sub: 'kandice',
                input: { user, assignedUser },
                obj: 'contact'
            },
            false
        );
    });

    test('should deny when manager does not have same location of user assigned to contact', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        const user = { id: 'bobby', attributes: { position: 'manager', accessTags: { location: [ { id: 'testing' }  ], department: [ { id: 'bebe' }]} }};
        const assignedUser = { id: 'billy', attributes: { accessTags: { location: [ { id: 'testing2' }  ], department: [ { id: 'bebe' }]} }};

        await testEnforce(
            enforcer,
            {
                sub: 'kevin',
                input: { assignedUser, user },
                obj: 'contact'
            },
            false
        );
    });

    test('should deny when user is not a manager', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        const user = { id: 'bobby', attributes: { position: 'sales', accessTags: { location: [ { id: 'testing' }  ], department: [ { id: 'bebe' }]} }};
        const assignedUser = { id: 'billy', attributes: { accessTags: { location: [ { id: 'testing' }  ], department: [ { id: 'bebe' }]} }};

        await testEnforce(
            enforcer,
            {
                sub: 'kandice',
                input: { assignedUser, user },
                obj: 'contact'
            },
            false
        );
    });
});
suite('Route Policy Enforcement,', () => {

    test('sales role has access to /sales/* routes', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        await testEnforce(
            enforcer,
            {
                sub: 'landre',
                input: null,
                obj: '/sales/dashboard/1234'
            },
            true
        );
    });
    test('input role has no access to /sales/* routes', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        await testEnforce(
            enforcer,
            {
                sub: 'kandice',
                input: null,
                obj: '/sales/dashboard'
            },
            false
        );
    });
    test('sales role has no access to /sales/contact/:id/backoffice route', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        await testEnforce(
            enforcer,
            {
                sub: 'landre',
                input: null,
                obj: '/sales/contact/1234/backoffice'
            },
            false
        );
    });
    test('manager role has access to /sales/* routes', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        await testEnforce(
            enforcer,
            {
                sub: 'kevin',
                input: null,
                obj: '/sales/dashboard'
            },
            true
        );
    });
});


suite('Add Policies,', () => {
    test('should allow when user is assigned to contact', async () => {
        const enforcer = await getTestEnforcer("test/casbin/model.conf", "test/casbin/policy.csv");

        const adapter = await MongooseAdapter.newSyncedAdapter('mongodb://localhost:27017/casbin', {useNewUrlParser: true, useUnifiedTopology: true});
        await sleep(1000);
        const e2 = await getTestEnforcer("test/casbin/model.conf", adapter);
        const p = await enforcer.getPolicy();
        console.log('all policies', p);
        await enforcer.addPolicy('/marketing', 'user', 'managerHasSameLocationAs', 'assignedUser', '_', '_', 'deny')
        const p2 = await e2.getPolicy();
        console.log('all policies2', p2);
        await e2.addPolicies(p);
        await e2.addGroupingPolicy('billy', 'role::sales');
        const p3 = await e2.getPolicy();
        // const saved = await enforcer.savePolicy();
        console.log('was saved', p3);
    });
});

async function testEnforce(e: Enforcer, params: { input: any; sub: any; obj: any;}, res: boolean) {
    expect(await e.enforce(params.input, params.sub, params.obj)).to.be.a.boolean().and
        .to.equal(res);
}

async function getTestEnforcer(...args: any[]): Promise<Enforcer> {
    const enforcer = await newEnforcer(...args);
    enforcer.addFunction("abacMatcherWrapper", AbacMatcher.AbacMatcherWrapper);
    return enforcer;
}

function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
