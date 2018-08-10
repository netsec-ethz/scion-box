import unittest
import update_gen
import copy


class TestUpdateGen(unittest.TestCase):
    def setUp(self):
        pass

    def test_dict_equal(self):
        d1 = {'obj': {
            'nested_obj': {'72': {
                'address': '127.0.0.4', 
                'InternalAddrIdx': 0,
            }}},
            'list': [{'nested_list': [{'f1': 10, 'f2': 'address1'}]}]}
        d2 = copy.deepcopy(d1)
        self.assertEqual(True, update_gen.dict_equal(d1, d2))
        
        d1['list'][0]['nested_list'][0]['f1'] += 1
        self.assertEqual(False, update_gen.dict_equal(d1, d2))
        d2['list'][0]['nested_list'][0]['f1'] += 1
        self.assertEqual(True, update_gen.dict_equal(d1, d2))

        d1['obj']['nested_obj']['extra'] = 'something'
        self.assertEqual(False, update_gen.dict_equal(d1, d2))
        del d1['obj']['nested_obj']['extra']
        self.assertEqual(True, update_gen.dict_equal(d1, d2))
        del d1['obj']['nested_obj']['72']
        self.assertEqual(False, update_gen.dict_equal(d1, d2))



if __name__ == '__main__':
    unittest.main()
