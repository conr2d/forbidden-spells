#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>
#include <eosio/system.hpp>
#include <eosio/producer_schedule.hpp>
#include <eosio/transaction.hpp>

using namespace eosio;

#ifdef __cplusplus
namespace eosio {
using capi_checksum256 = std::array<uint8_t,32> __attribute__ ((aligned(16)));
}
#endif

struct block_header {
   block_timestamp                           timestamp;
   name                                      producer;
   uint16_t                                  confirmed = 0;
   capi_checksum256                          previous;
   capi_checksum256                          transaction_mroot;
   capi_checksum256                          action_mroot;
   uint32_t                                  schedule_version = 0;
   std::optional<eosio::producer_schedule>   new_producers;
   std::vector<std::pair<uint16_t,std::vector<char>>> header_extensions;

   EOSLIB_SERIALIZE(block_header, (timestamp)(producer)(confirmed)(previous)(transaction_mroot)(action_mroot)
                                  (schedule_version)(new_producers)(header_extensions))
};

class [[eosio::contract]] blockhash : public contract {
public:
   using contract::contract;

   struct [[eosio::table("blockid")]] block_id {
      checksum256 value;

      uint64_t primary_key() const {
         return static_cast<uint64_t>(value.data()[0] >> (sizeof(uint32_t) * 8 * 3));
      }
   };

   using block_ids = eosio::multi_index<"blockid"_n, block_id>;

   [[eosio::action]]
   void onblock(ignore<block_header>) {
      require_auth(get_self());

      block_ids ids(get_self(), get_self().value);

      auto begin = ids.begin();
      auto end = ids.end();

      // Keep the latest 256 block ids
      if ((begin != end) && (--end != begin)) {
         while (end->primary_key() > begin->primary_key() + 256) {
            begin = ids.erase(begin);
         }
      }

      ids.emplace(get_self(), [&](auto& id) {
         id.value = eosio::sha256(get_datastream().pos(), action_data_size());
         uint32_t block_num = tapos_block_num();

         auto dst = reinterpret_cast<char*>(id.value.data()) + (sizeof(uint32_t) * 3);
         auto src = reinterpret_cast<char*>(&block_num);

         std::copy(src, src + sizeof(uint32_t), dst);
      });
   }
};
