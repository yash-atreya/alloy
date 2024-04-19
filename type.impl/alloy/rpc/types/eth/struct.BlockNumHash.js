(function() {var type_impls = {
"alloy":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#443\">source</a><a href=\"#impl-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#445\">source</a><h4 class=\"code-header\">pub const fn <a href=\"alloy/rpc/types/eth/struct.BlockNumHash.html#tymethod.new\" class=\"fn\">new</a>(number: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>, hash: <a class=\"struct\" href=\"alloy/primitives/struct.FixedBytes.html\" title=\"struct alloy::primitives::FixedBytes\">FixedBytes</a>&lt;32&gt;) -&gt; <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h4></section></summary><div class=\"docblock\"><p>Creates a new <code>BlockNumHash</code> from a block number and hash.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.into_components\" class=\"method\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#450\">source</a><h4 class=\"code-header\">pub const fn <a href=\"alloy/rpc/types/eth/struct.BlockNumHash.html#tymethod.into_components\" class=\"fn\">into_components</a>(self) -&gt; (<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>, <a class=\"struct\" href=\"alloy/primitives/struct.FixedBytes.html\" title=\"struct alloy::primitives::FixedBytes\">FixedBytes</a>&lt;32&gt;)</h4></section></summary><div class=\"docblock\"><p>Consumes <code>Self</code> and returns <a href=\"alloy/primitives/type.BlockNumber.html\" title=\"type alloy::primitives::BlockNumber\"><code>BlockNumber</code></a>, <a href=\"alloy/primitives/type.BlockHash.html\" title=\"type alloy::primitives::BlockHash\"><code>BlockHash</code></a></p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.matches_block_or_num\" class=\"method\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#455\">source</a><h4 class=\"code-header\">pub fn <a href=\"alloy/rpc/types/eth/struct.BlockNumHash.html#tymethod.matches_block_or_num\" class=\"fn\">matches_block_or_num</a>(&amp;self, block: &amp;<a class=\"enum\" href=\"alloy/rpc/types/eth/enum.BlockHashOrNumber.html\" title=\"enum alloy::rpc::types::eth::BlockHashOrNumber\">BlockHashOrNumber</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class=\"docblock\"><p>Returns whether or not the block matches the given <a href=\"alloy/rpc/types/eth/enum.BlockHashOrNumber.html\" title=\"enum alloy::rpc::types::eth::BlockHashOrNumber\">BlockHashOrNumber</a>.</p>\n</div></details></div></details>",0,"alloy::rpc::types::eth::ForkBlock"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#impl-Clone-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","alloy::rpc::types::eth::ForkBlock"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#437\">source</a><a href=\"#impl-Debug-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#438\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Error.html\" title=\"struct core::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","alloy::rpc::types::eth::ForkBlock"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#impl-Default-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h4></section></summary><div class='docblock'>Returns the “default value” for a type. <a href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html#tymethod.default\">Read more</a></div></details></div></details>","Default","alloy::rpc::types::eth::ForkBlock"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3C(FixedBytes%3C32%3E,+u64)%3E-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#469\">source</a><a href=\"#impl-From%3C(FixedBytes%3C32%3E,+u64)%3E-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;(<a class=\"struct\" href=\"alloy/primitives/struct.FixedBytes.html\" title=\"struct alloy::primitives::FixedBytes\">FixedBytes</a>&lt;32&gt;, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>)&gt; for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#470\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(val: (<a class=\"struct\" href=\"alloy/primitives/struct.FixedBytes.html\" title=\"struct alloy::primitives::FixedBytes\">FixedBytes</a>&lt;32&gt;, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>)) -&gt; <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<(FixedBytes<32>, u64)>","alloy::rpc::types::eth::ForkBlock"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3C(u64,+FixedBytes%3C32%3E)%3E-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#463\">source</a><a href=\"#impl-From%3C(u64,+FixedBytes%3C32%3E)%3E-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;(<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>, <a class=\"struct\" href=\"alloy/primitives/struct.FixedBytes.html\" title=\"struct alloy::primitives::FixedBytes\">FixedBytes</a>&lt;32&gt;)&gt; for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#464\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(val: (<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u64.html\">u64</a>, <a class=\"struct\" href=\"alloy/primitives/struct.FixedBytes.html\" title=\"struct alloy::primitives::FixedBytes\">FixedBytes</a>&lt;32&gt;)) -&gt; <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<(u64, FixedBytes<32>)>","alloy::rpc::types::eth::ForkBlock"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Hash-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#impl-Hash-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#method.hash\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#tymethod.hash\" class=\"fn\">hash</a>&lt;__H&gt;(&amp;self, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut __H</a>)<div class=\"where\">where\n    __H: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>,</div></h4></section></summary><div class='docblock'>Feeds this value into the given <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#tymethod.hash\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash_slice\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.3.0\">1.3.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/hash/mod.rs.html#238-240\">source</a></span><a href=\"#method.hash_slice\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#method.hash_slice\" class=\"fn\">hash_slice</a>&lt;H&gt;(data: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.slice.html\">[Self]</a>, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut H</a>)<div class=\"where\">where\n    H: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>,\n    Self: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h4></section></summary><div class='docblock'>Feeds a slice of this type into the given <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#method.hash_slice\">Read more</a></div></details></div></details>","Hash","alloy::rpc::types::eth::ForkBlock"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#impl-PartialEq-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#263\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","alloy::rpc::types::eth::ForkBlock"],["<section id=\"impl-Copy-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#impl-Copy-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section>","Copy","alloy::rpc::types::eth::ForkBlock"],["<section id=\"impl-Eq-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#impl-Eq-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section>","Eq","alloy::rpc::types::eth::ForkBlock"],["<section id=\"impl-StructuralPartialEq-for-BlockNumHash\" class=\"impl\"><a class=\"src rightside\" href=\"src/alloy_rpc_types/eth/block.rs.html#426\">source</a><a href=\"#impl-StructuralPartialEq-for-BlockNumHash\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"alloy/rpc/types/eth/struct.BlockNumHash.html\" title=\"struct alloy::rpc::types::eth::BlockNumHash\">BlockNumHash</a></h3></section>","StructuralPartialEq","alloy::rpc::types::eth::ForkBlock"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()